"""Resolve output destinations shared by the GUI preview, verifier, and command builders."""

import os
from pathlib import Path

from libasadt4.gui_models import OUTPUT_KEYS, RECON_FIELDS
from libasadt4.tool_config import ArgumentIssue, configured_report_filename


def check_writable(path, directory=False):
    """Check whether the process can write at a destination.

    For a directory, require write and traversal access. For a file, check the existing
    file or its parent if new. Raise `PermissionError` with the absolute path.
    """
    path = Path(path).absolute()
    if directory:
        writable = path.is_dir() and os.access(path, os.W_OK | os.X_OK)
    elif path.exists() or path.is_symlink():
        writable = path.is_file() and os.access(path, os.W_OK)
    else:
        writable = path.parent.is_dir() and os.access(path.parent, os.W_OK | os.X_OK)
    if not writable:
        raise PermissionError(f'Cannot write to this path: {path}')


def report_path(tool, values, config):
    """Build the output argument for a scanner.

    Read the directory from the tool's output field and join it with the configured
    filename. DNSRecon derives the extension from its selected format. For Nmap `oA`,
    the returned string is the basename.
    """
    directory = values[OUTPUT_KEYS[tool]]
    filename = configured_report_filename(tool, config or {})
    if tool == 'nmap' and '%' in os.fspath(directory):
        raise ArgumentIssue(OUTPUT_KEYS[tool], 'Nmap expands % in output paths. Choose a directory without %.')
    if tool == 'dnsrecon':
        stem, extension = os.path.splitext(filename)
        if extension.lower() in ('.json', '.csv', '.xml'):
            filename = stem
        filename += '.' + values[5][0].lower()
    return os.path.join(directory, filename)


def report_files(tool, values, config):
    """Return the concrete report paths the selected tool can overwrite.

    Expand the Nmap oA basename into .nmap, .xml and .gnmap paths. MSFPC chooses
    filenames during execution, so its list is empty. Nmap and Nikto also return an
    empty list when config is None.
    """
    if tool == 'msfpc' or (config is None and tool in ('nikto', 'nmap')):
        return []
    path = report_path(tool, values, config)
    if tool == 'nmap' and config['ScriptOutput']['nmap_fullscan_output_format'] == 'oA':
        return [Path(path + suffix) for suffix in ('.nmap', '.xml', '.gnmap')]
    return [Path(path)]


def check_tool_output(tool, values, config):
    """Verify access to the report directory and each known destination.

    Use `report_files` to expand multi-format output before testing writability.
    Propagate filesystem failures to the terminal or Qt caller.
    """
    directory = Path(values[OUTPUT_KEYS[tool]])
    check_writable(directory, directory=True)
    for path in report_files(tool, values, config):
        check_writable(path)
        if path.is_symlink() and not path.resolve().is_relative_to(directory.resolve()):
            raise PermissionError(f'Report links outside the output directory: {path}')


def overwrite_question(tool, values, config):
    """Describe the overwrite decision for this submission.

    Return a question listing existing reports, or a directory warning for MSFPC when
    nonempty. Return `None` when no confirmation is needed.
    """
    if tool == 'msfpc':
        directory = Path(values[OUTPUT_KEYS[tool]]).absolute()
        if any(directory.iterdir()):
            return (f'MSFPC chooses filenames during generation. Existing files in {directory} '
                    'may be overwritten. Continue?')
    else:
        existing = [str(path.absolute()) for path in report_files(tool, values, config)
                    if os.path.lexists(path)]
        if existing:
            return 'Would you like to overwrite the following existing report files?\n' + '\n'.join(existing)
    return None


def prepare_tool_output(tool, values, config, confirm_create):
    """Prepare the output directory and verify access to each report destination.

    For tools in RECON_FIELDS, verify that selected input files are readable and that an
    existing report does not refer to an input file. Call confirm_create(directory) with
    a Path before creating a missing directory. Return True when all output checks pass
    or False when the caller declines creation. Field errors identify the affected key,
    and filesystem errors propagate to the caller.
    """
    # Validate paths before offering to create a directory, even with ArgVerify off.
    files = report_files(tool, values, config)
    if tool in RECON_FIELDS:
        report = files[0]
        for field in RECON_FIELDS[tool]:
            if field.get('input_file') and values[field['key']]:
                source = Path(values[field['key']])
                if not source.is_file() or not os.access(source, os.R_OK):
                    raise ArgumentIssue(field['key'], f"{field['label']}: select a readable file: {source}")
                if report.exists() and source.samefile(report):
                    raise ArgumentIssue(OUTPUT_KEYS[tool], f'Select a report separate from the input file: {source}')
    directory = Path(values[OUTPUT_KEYS[tool]])
    if not directory.is_dir():
        if os.path.lexists(directory):
            raise OSError(f'Select a directory. This path is not a directory: {directory.absolute()}')
        if not confirm_create(directory):
            return False
        directory.mkdir(parents=True, exist_ok=True)
    check_tool_output(tool, values, config)
    return True
