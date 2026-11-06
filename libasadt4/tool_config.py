"""Validation shared by TOML defaults, forms and tool arguments."""

import math
import re
from pathlib import PureWindowsPath

from libasadt4.gui_models import RECON_FIELDS, REQUIRED_KEYS, TOOL_MODELS, TOOL_NAMES


BOOLEAN_SETTINGS = {
    'nmap': {
        'nmap_enable': 'Enable Nmap',
        'nmap_updatensedb': 'Update the NSE Script Database before Scanning',
        'nmap_nsedebug_enable': 'Trace NSE Script Traffic',
        'nmap_nsescriptscan_enable': 'Enable NSE Script Scanning',
        'nmap_assumesudoperms_enable': 'Assume Privileged Nmap Execution',
    },
    'nikto': {'nikto_enable': 'Enable Nikto', 'nikto_nointeractive': 'Disable Interactive Prompts'},
    'dnsrecon': {'dnsrecon_enable': 'Enable DNSRecon'},
    'msfpc': {'msfpc_enable': 'Enable MSFPC', 'msfpc_verboseout': 'Show Verbose Output'},
}

OUTPUT_PREFIX = {'nmap': 'nmap_fullscan_output_', 'nikto': 'nikto_default_output_'}
BOOLEAN_SETTINGS.update({tool: {tool + '_enable': 'Enable ' + TOOL_NAMES[tool]} for tool in RECON_FIELDS})


def configured_report_filename(tool, config):
    """Resolve and validate the report basename used by the tool.

    Read the tool's key from `ScriptOutput`, falling back to JSON for DNSRecon and
    WPScan or text for other tools. Reject empty names, directory components, dot
    entries and NUL with `ValueError`.
    """
    output = config.get('ScriptOutput', {})
    if not isinstance(output, dict):
        raise ValueError('ScriptOutput must be a TOML table')
    if tool in OUTPUT_PREFIX:
        key = OUTPUT_PREFIX[tool] + 'filename'
        filename = output.get(key)
    else:
        key = tool + '_default_output_filename'
        extension = 'json' if tool in ('wpscan', 'dnsrecon') else 'txt'
        filename = output.get(key, f'{tool}.{extension}')
    if (not isinstance(filename, str) or not filename.strip() or filename in ('.', '..')
            or PureWindowsPath(filename).name != filename or '\x00' in filename):
        raise ValueError(f'ScriptOutput.{key}: enter a filename without a directory')
    if tool == 'nmap' and '%' in filename:
        raise ValueError(f'ScriptOutput.{key}: Nmap expands % in output paths. Choose a filename without %.')
    return filename


def dnsrecon_output_filename(config):
    """Return the configured DNSRecon report basename.

    Delegate to the common filename validator with the DNSRecon key. The output path
    builder applies the run's selected format later.
    """
    return configured_report_filename('dnsrecon', config)


def output_formats(tool, rules):
    """List native output format identifiers for Nmap or Nikto.

    Return a tuple suitable for both validation and the form. Nmap uses its native
    output switches. Nikto's legacy profile also permits `nbe`.
    """
    if tool == 'nmap':
        return ('oN', 'oX', 'oG', 'oA', 'oS')
    formats = ('csv', 'json', 'htm', 'sql', 'txt', 'xml')
    return formats + ('nbe',) if rules.get('nikto_cli_profile', 'legacy') == 'legacy' else formats


def enabled(value):
    """Return the boolean represented by a TOML switch.

    Accept True, False and the case-sensitive legacy strings 'True' and 'False'. Raise
    ValueError for any other value.
    """
    if isinstance(value, bool):
        return value
    if value in ('True', 'False'):
        return value == 'True'
    raise ValueError("expected true, false, 'True' or 'False'")


class ArgumentIssue(ValueError):
    """Validation error associated with an editable tool field.

    key is the integer identifier from TOOL_MODELS. The terminal uses it to prompt for a
    replacement, and the form uses it to focus the control. The exception message is
    displayed to the user.
    """

    def __init__(self, key, message):
        """Attach the field key to its diagnostic.

        Pass `message` to `ValueError` and store `key` for focus, selection or retry.
        """
        super().__init__(message)
        self.key = key


def missing_required_fields(tool, values):
    """Find unfilled required fields in display order.

    Use the tool's required keys against the submitted mapping or sequence. Return model
    records for absent, false-like or whitespace-only values.
    """
    missing = []
    for field in TOOL_MODELS[tool]:
        key = field['key']
        if key in REQUIRED_KEYS[tool]:
            try:
                value = values[key]
            except (KeyError, IndexError):
                value = None
            if not value or (isinstance(value, str) and not value.strip()):
                missing.append(field)
    return missing


def validate_field(field, value):
    """Check a scalar value against its field model.

    Validate checkbox booleans, integer limits, choice membership, native input strings
    and absolute Nikto root paths as applicable. Raise `ValueError` with the reason.
    """
    if field['kind'] == 'Checkbox':
        enabled(value)
    elif field['kind'] == 'Slider':
        lower, upper = field['range']
        if type(value) is not int or not lower <= value <= upper:
            raise ValueError(f'expected a whole number from {lower} to {upper}')
    elif field['kind'] == 'Listbox':
        if value not in field['choices']:
            raise ValueError('choose ' + ', '.join(field['choices']))
    elif not isinstance(value, str):
        raise ValueError('expected a string')
    elif field.get('native_input') and (value.lstrip().startswith('-') or '\x00' in value):
        raise ValueError('enter a value without a leading dash or NUL character')
    elif field['setting'] == 'root_path' and value and not value.startswith('/'):
        raise ValueError('start the path with /, for example /portal')


def normalize_slider(field, value):
    """Convert legacy slider numbers into validated integers.

    Older fields accept an in-range numeric value that can be truncated. New settings
    require an integer. Return the validated value or raise `ValueError`.
    """
    # Original slider controls returned numeric values that callers could truncate.
    if field.get('legacy_numeric') and type(value) not in (int, bool):
        lower, upper = field['range']
        try:
            whole = math.trunc(value)
            if lower <= value <= upper:
                value = whole
        except (TypeError, ValueError, OverflowError):
            pass
    validate_field(field, value)
    return value


def validated_defaults(tool, config):
    """Check the optional TOML defaults against the tool's settings.

    Return the defaults table or an empty mapping. Unknown keys and invalid values raise
    `ValueError` identifying the setting.
    """
    defaults = config.get('Defaults', {})
    if not isinstance(defaults, dict):
        raise ValueError('Defaults must be a TOML table')
    fields = {field['setting']: field for field in TOOL_MODELS[tool] if 'setting' in field}
    for key, value in defaults.items():
        if key not in fields:
            raise ValueError(f'Defaults.{key}: unknown setting')
        try:
            validate_field(fields[key], value)
        except ValueError as error:
            raise ValueError(f'Defaults.{key}: {error}') from error
    return defaults


def initial_values(tool, config):
    """Return a fresh field dictionary for the terminal or Qt form.

    Use integer model keys and apply validated TOML defaults to the corresponding
    settings. Choice fields contain a one-element list, radio selections use the model's
    boolean defaults, and text inputs are stripped. Nikto's CLI profile determines the
    initial cookie switch.
    """
    defaults = validated_defaults(tool, config or {})
    values = {}
    for field in TOOL_MODELS[tool]:
        key = field['key']
        value = defaults.get(field.get('setting'), field.get('default_value'))
        kind = field['kind']
        if kind == 'Listbox':
            value = [value if value is not None else field['choices'][0]]
        elif kind == 'Radio':
            value = field.get('default', False)
        elif kind == 'Checkbox':
            value = enabled(value) if value is not None else False
            if tool == 'nikto' and key == 7:
                value = (config or {}).get('ScriptEnablers', {}).get('nikto_cli_profile') == 'current'
        elif kind == 'Input':
            value = (value or '').strip()
        values[key] = value
    return values


def validate_tool_config(tool, config):
    """Validate the tool's TOML before showing a form or starting a run.

    Check enablers, defaults and report settings. Nmap and Nikto have format-specific
    rules, including Nikto profile and display codes. Raise `ValueError` on an invalid
    setting.
    """
    rules = config.get('ScriptEnablers')
    if not isinstance(rules, dict):
        raise ValueError('ScriptEnablers must be a TOML table')
    for key in BOOLEAN_SETTINGS[tool]:
        try:
            enabled(rules.get(key))
        except ValueError as error:
            raise ValueError(f'ScriptEnablers.{key}: {error}') from error
    validated_defaults(tool, config)
    if tool == 'dnsrecon' or tool in RECON_FIELDS:
        configured_report_filename(tool, config)
    if tool not in ('nmap', 'nikto'):
        return
    output = config.get('ScriptOutput')
    if not isinstance(output, dict):
        raise ValueError('ScriptOutput must be a TOML table')
    if tool == 'nikto':
        profile = rules.get('nikto_cli_profile', 'legacy')
        if profile not in ('current', 'legacy'):
            raise ValueError('ScriptEnablers.nikto_cli_profile: choose current or legacy')
        display = rules.get('nikto_displaytype')
        if not isinstance(display, str) or not re.fullmatch('[1-4DEPSV]+', display):
            raise ValueError('ScriptEnablers.nikto_displaytype: use one or more of 1234DEPSV')
    formats = output_formats(tool, rules)
    prefix = OUTPUT_PREFIX[tool]
    if output.get(prefix + 'format') not in formats:
        raise ValueError(f'ScriptOutput.{prefix}format: choose ' + ', '.join(formats))
    configured_report_filename(tool, config)


def validate_packages(packages):
    """Validate the dependency list before it reaches APT.

    Require a nonempty list of package names matching the allowed Debian-style spelling.
    Reject option-like entries and trailing removal operators with `ValueError`.
    """
    if not isinstance(packages, list) or not packages:
        raise ValueError('APT_DEP.dependency_list: expected a nonempty array of package names')
    for name in packages:
        # APT interprets a trailing minus as a request to remove a package.
        if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.+-]*[a-z0-9.+]', name):
            raise ValueError(f'APT_DEP.dependency_list: invalid package name {name!r}')
