#!/usr/bin/env python3
"""ASADT command-line interface for tool discovery, configuration and execution.

The Typer application cli_host exposes four commands. The run command lists tools, opens
the selected tool's Qt form, or runs it in the terminal when --target is supplied. The
cnfedit command opens a saved TOML file, version displays release metadata, and update
checks for a release or installs the configured APT packages.

MODULES maps each module name to a runner class. The runner's submodules list supplies
the tool names, and the pair identifies config/<module>/<tool>.toml relative to this
file. A scanner added to an existing runner appears in the CLI through that list. A new
module family also needs an entry in MODULES and a matching configuration directory.

Runner classes accept the ToolModule constructor arguments and propagate the native exit
status through cmdgen(). Import Qt in the form branch to keep terminal commands
available on hosts without a graphical session.
"""

import platform
import sys
from contextlib import nullcontext
from io import BytesIO
from pathlib import Path
from textwrap import indent
from typing import Annotated

# Redirected Windows streams also need UTF-8 for the CLI banners.
for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, 'reconfigure'):
        stream.reconfigure(encoding='utf-8')

try:

    import typer as TypeCLI
    import os

    from rich import print
    from rich.console import Console as rcon
    from rich.padding import Padding
    from rich.prompt import Prompt
    from rich.text import Text

    from libasadt4.mainprog import CnfEdit
    from libasadt4.mainprog import TOML_Loader
    from libasadt4.mainprog import ProgBanner
    from libasadt4.mainprog import ProgUpdate

    from libasadt4 import modules_main
    from libasadt4.gui_models import OUTPUT_KEYS, RADIO_DEFAULTS, TOOL_MODELS
    from libasadt4.output_paths import overwrite_question, prepare_tool_output
    from libasadt4.privileges import privilege_message, privilege_reasons, script_permissions
    from libasadt4.tool_config import enabled, initial_values, validate_tool_config

    cli_host = TypeCLI.Typer()
    con_host = rcon()
    MODULES = {'scantool': modules_main.ScanTool, 'hacktool': modules_main.HackTool}

    local_config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config')

    config_editor = CnfEdit(5)

except ImportError as ErrorID:

    print(f'Python Import Error: {ErrorID}')

    raise SystemExit(3)


def load_main_config():
    """Return the loader for config/scriptinfo.toml beside the entry point.

    If the file cannot be read or parsed, print the loader diagnostic and exit with
    status 4.
    """
    config = TOML_Loader(local_config_dir).loadfile('scriptinfo.toml')
    if not config.status_ok:
        print(f'[red bold]\nTOML_Loader Error > Failed To Load Configuration File "{config.parser_cnffileid}"!\nReason > {config.status_data}\n[/red bold]')
        raise SystemExit(4)
    return config

@cli_host.command('cnfedit', help='Choose a saved TOML file to open in the configuration editor.')
def cnfedit():
    """Open a saved configuration file selected by number.

    List TOML files recursively before parsing so users can repair malformed files.
    Selecting a file delegates to CnfEdit.run_editor. Selecting q or finding an empty
    configuration directory returns to the caller.
    """
    config_editor.display_banner()
    config_dir = Path(local_config_dir)
    files = sorted(path for path in config_dir.rglob('*.toml') if path.is_file())
    if not files:
        con_host.print('No TOML configuration files found.')
        return

    con_host.print('[bold]Configuration files[/bold]')
    for number, path in enumerate(files, start=1):
        con_host.print(f'{number}. {path.relative_to(config_dir).as_posix()}', markup=False)
    con_host.print('q. Quit')
    choices = [str(number) for number in range(1, len(files) + 1)]
    choice = Prompt.ask('Select a file', choices=[*choices, 'q'], show_choices=False)
    if choice != 'q':
        config_editor.run_editor(str(files[int(choice) - 1]))

def resolve_tool(name, tool):
    """Return the (module, tool) pair for a qualified or unique short name.

    A short name must occur in exactly one runner's submodules list. Unknown and
    ambiguous names exit through run_error with status 3.
    """
    if name in MODULES and tool in MODULES[name].submodules:
        return name, tool
    if tool is None:
        matches = [module for module, runner in MODULES.items() if name in runner.submodules]
        if len(matches) == 1:
            return matches[0], name
        if matches:
            run_error(f'{name} belongs to multiple modules. Specify one of: {", ".join(matches)}')
    if name in MODULES:
        run_error(f'Unknown {name} tool {tool!r}. Choose from: {", ".join(MODULES[name].submodules)}')
    run_error(f'Unknown module or tool {name!r}. Use "run" to list available tools.')


def run_error(message):
    """End an invalid CLI invocation with status 3.

    Print `message` as literal Rich text so user input cannot alter the diagnostic's
    formatting.
    """
    con_host.print(Text(message, style='bold red'))
    raise SystemExit(3)


def confirm_run(question, **prompt_options):
    """Ask for permission to continue a terminal operation.

    Forward `prompt_options` to Typer and default to No. Return a boolean, treating EOF,
    interruption and an aborted prompt as refusal.
    """
    try:
        return TypeCLI.confirm(question, default=False, **prompt_options)
    except (EOFError, KeyboardInterrupt, TypeCLI.Abort):
        return False


def prepare_terminal_run(runner_type, tool, config, values, debugger, *, verify=True):
    """Return a runner prepared from the submitted terminal values.

    On an interactive terminal, a field-specific VerificationFailed offers a retry using
    the field's model key. A radio choice updates its whole group, a list selection
    becomes a one-element list, and sensitive inputs use a hidden prompt. Each retry
    constructs a runner from the corrected values. An unkeyed error, a declined repair
    or noninteractive input propagates VerificationFailed.

    With verify=False, the CLI prepares the output directory before constructing the
    runner. asadtexec checks the prepared report paths for overwrites before execution.
    """
    if not verify:
        try:
            ready = prepare_tool_output(tool, values, config,
                                        lambda directory: confirm_run(f'Create output directory {directory}?'))
        except (OSError, ValueError) as error:
            run_error(str(error))
        if not ready:
            raise SystemExit(3)
        return runner_type(tool, config, values, debugger, ioverify=False)

    while True:
        try:
            return runner_type(tool, config, values, debugger)
        except modules_main.VerificationFailed as failure:
            issue = failure.issue
            if not isinstance(issue, modules_main.ArgumentIssue) or sys.stdin is None or not sys.stdin.isatty():
                raise
            field = next(field for field in TOOL_MODELS[tool] if field['key'] == issue.key)
            label = field['label'].strip().rstrip('*')
            if not confirm_run(f'Edit {label} and try again?'):
                raise
            try:
                kind = field['kind']
                if kind == 'Radio':
                    group = field['group_id']
                    buttons = [item for item in TOOL_MODELS[tool] if item.get('group_id') == group]
                    choices = [item['label'].strip() for item in buttons]
                    if group in RADIO_DEFAULTS:
                        choices.append(RADIO_DEFAULTS[group])
                    selected = Prompt.ask('Choose an option', choices=choices, case_sensitive=False)
                    for item in buttons:
                        values[item['key']] = item['label'].strip() == selected
                    continue
                prompt_type = {'Slider': int, 'Checkbox': bool}.get(kind, str)
                replacement = TypeCLI.prompt(label, type=prompt_type, hide_input=bool(field.get('sensitive_flag')),
                                             default='' if prompt_type is str else None, show_default=False)
            except (EOFError, KeyboardInterrupt, TypeCLI.Abort):
                raise SystemExit(3) from None
            if isinstance(replacement, str):
                replacement = replacement.strip()
            values[issue.key] = [replacement] if kind == 'Listbox' else replacement


def terminal_values(tool, config, target, output_dir, ports, resolvers, script=None):
    """Map terminal options to the integer-keyed submission used by the form.

    Start with initial_values and set field 0 to the target (the domain-list path for
    MassDNS). OUTPUT_KEYS identifies the output directory, which defaults to the
    caller's working directory and is stored as an absolute path. Field 1 holds ports
    for Nmap, Nikto and MSFPC or the resolver list for MassDNS. Field 2 holds Nmap's NSE
    selector.

    Nmap requires an explicit port expression. MassDNS accepts a resolver list from the
    command line or its configured defaults. Missing required options and switches
    incompatible with the selected tool exit with status 3.

    To expose another terminal option, declare it on asadtexec, include it in the
    --target check, and map it here using the field's model key and value type.
    """
    values = initial_values(tool, config)
    if output_dir is not None and not output_dir.strip():
        run_error('--output-dir needs a directory name.')
    values[OUTPUT_KEYS[tool]] = str(Path(output_dir or '.').absolute())
    if ports is not None and tool not in ('nmap', 'nikto', 'msfpc'):
        run_error(f'--ports does not apply to {tool}.')
    if resolvers is not None and tool != 'massdns':
        run_error(f'--resolvers does not apply to {tool}.')
    if script is not None:
        if tool != 'nmap':
            run_error(f'--script does not apply to {tool}.')
        if not enabled(config['ScriptEnablers']['nmap_nsescriptscan_enable']):
            run_error('--script requires nmap_nsescriptscan_enable in the Nmap configuration.')
    for key, option, value in ((0, '--target', target), (1, '--ports', ports),
                               (1, '--resolvers', resolvers), (2, '--script', script)):
        if value is None:
            continue
        value = value.strip()
        open_port_range = option == '--ports' and tool == 'nmap'
        if not value or (value.startswith('-') and not open_port_range) or '\x00' in value:
            run_error(f'{option} needs a value without a leading dash or NUL character.')
        values[key] = value
    if tool == 'nmap' and not ports:
        run_error('Specify the Nmap ports, for example --ports 80,443.')
    if tool == 'massdns' and not values[1]:
        run_error('Specify the MassDNS resolver list with --resolvers FILE.')
    return values


@cli_host.command('run', help=(
    'List tools, open a tool form, or execute in the terminal with --target. '
    'Examples: run scantool, run nmap, run nmap --target localhost --ports 80.'
))
def asadtexec(
    module_name: Annotated[str | None, TypeCLI.Argument(metavar='[MODULE_OR_TOOL]')] = None,
    tool_name: Annotated[str | None, TypeCLI.Argument(metavar='[TOOL]')] = None,
    debugger: Annotated[bool, TypeCLI.Option(help='Trace configuration, verification, commands and exit status to stderr.')] = False,
    target: Annotated[str | None, TypeCLI.Option(help='Run without Qt. Supply the target, or the domain list for massdns.')] = None,
    output_dir: Annotated[str | None, TypeCLI.Option(help='Terminal output directory (default: current directory).')] = None,
    ports: Annotated[str | None, TypeCLI.Option('--ports', '--port', help='Nmap ports, Nikto port or MSFPC connection port.')] = None,
    resolvers: Annotated[str | None, TypeCLI.Option(help='MassDNS resolver list file.')] = None,
    script: Annotated[str | None, TypeCLI.Option(help='Nmap NSE script name or expression. Quote expressions containing spaces.')] = None,
    no_argverify: Annotated[bool, TypeCLI.Option('--no-argverify', help='Skip ArgVerify for this --target run.')] = False,
):
    """List registered tools or dispatch a single terminal or Qt submission.

    Listing returns before metadata or tool configuration is loaded. For a selected
    tool, load and validate its TOML, then evaluate privilege requirements. For terminal
    runs, privilege_reasons uses the submitted values. Before opening Qt, it uses the
    configuration and default scan method. Pass acknowledged reasons to the form so
    edits that introduce additional requirements trigger a new prompt.

    In the terminal, prepare_terminal_run returns the runner whose arguments determine
    the overwrite prompt. In Qt, DISPLAY_UI_MODEL prepares the runner and obtains
    consent while fields are editable. After the dialog closes, a quit action exits, an
    edit action opens the saved TOML in CnfEdit, and an execute action starts
    result.runner with the form's configuration and verification choice.

    Declining a terminal privilege or overwrite prompt, or cancelling the form, exits
    with status 1. Invalid CLI input or tool configuration exits with status 3. Failure
    to load the main TOML exits with status 4. Once execution starts, cmdgen propagates
    the native status, including failure of a preliminary Nmap command.
    """
    if target is None and (no_argverify or any(option is not None for option in (output_dir, ports, resolvers, script))):
        run_error('Supply --target to execute with terminal options.')
    if tool_name is None and (module_name is None or module_name in MODULES):
        if target is not None:
            run_error('Choose a tool to execute, for example: run nmap --target localhost --ports 80.')
        for name, runner in MODULES.items():
            if module_name is None or module_name == name:
                con_host.print(f'{name}: {", ".join(runner.submodules)}', markup=False)
        con_host.print('Open a form with "run TOOL". Execute in the terminal with "run TOOL --target TARGET".')
        return

    module_name, tool_name = resolve_tool(module_name, tool_name)
    module_active = MODULES[module_name]
    main_config = load_main_config()
    ProgBanner(main_config.dictionary['script_data']['script_version']).display_banner(banner_type='short', debugger=debugger)

    relative_path = f'{module_name}/{tool_name}.toml'
    if debugger:
        modules_main.print_debug(script_permissions(__file__))
        modules_main.print_debug(f'Python: {platform.python_implementation()} {platform.python_version()}')
        modules_main.print_debug(f'Interpreter: {sys.executable}')
        venv = sys.prefix if sys.prefix != sys.base_prefix else 'none'
        modules_main.print_debug(f'Virtual environment: {venv}')
        modules_main.print_debug(f'Configuration file: {Path(local_config_dir, relative_path)}')
        modules_main.print_debug(f'modules_main selected {module_active.__name__} for {tool_name}')
    loaded = TOML_Loader(local_config_dir).loadfile(relative_path)
    if not loaded.status_ok:
        run_error(f'{relative_path}: {loaded.status_data}')
    config = loaded.dictionary
    try:
        validate_tool_config(tool_name, config)
    except ValueError as error:
        run_error(f'{relative_path}: {error}')

    values = None
    if target is not None:
        if not enabled(config['ScriptEnablers'][tool_name + '_enable']):
            run_error(f'{tool_name} is disabled in {relative_path}.')
        values = terminal_values(tool_name, config, target, output_dir, ports, resolvers, script)
    reasons = privilege_reasons(tool_name, config, values)
    if reasons:
        if values is None:
            message = privilege_message(reasons)
        else:
            message = '\n'.join([*reasons, 'For elevated execution, rerun the same arguments with sudo .venv/bin/python asadt.py.'])
        warning = Text('[!] Privilege warning\n' + message, style='bold yellow')
        con_host.print(Padding(warning, (0, 0, 0, 2), expand=False))
        action = 'Execute' if values is not None else 'Open the GUI'
        if not confirm_run(f'{action} with current permissions?'):
            raise SystemExit(1)

    if values is not None:
        runner = prepare_terminal_run(module_active, tool_name, config, values, debugger, verify=not no_argverify)
        try:
            question = overwrite_question(tool_name, runner.execute_arguments, config)
        except OSError as error:
            run_error(str(error))
        if question:
            warning = '  [!] OVERWRITE WARNING\n' + indent(question, '      ') + ' y/n'
            prompt = TypeCLI.style(warning, fg=TypeCLI.colors.YELLOW, bold=True)
            if not confirm_run(prompt, show_default=False, prompt_suffix=' '):
                raise SystemExit(1)
            TypeCLI.echo()
        return runner.cmdgen()

    if debugger:
        modules_main.print_debug('ArgVerify is active by default. To disable it for this run, '
                                 'open Runtime config and clear "Verify arguments (ArgVerify)" before clicking Run.')
    message = Text(f'  Displaying UI... {module_name} / {tool_name}', style='bold red')
    console = modules_main.gui_console(debugger)
    if console.is_interactive:
        status = console.status(message, spinner='arc', spinner_style='red')
    else:
        console.print(message)
        status = nullcontext()
    with status:
        from libasadt4.displayboxhandler import DisplayBoxHandler_Service
        handler = DisplayBoxHandler_Service(debug=modules_main.print_debug if debugger else None)
        result = handler.DISPLAY_UI_MODEL(tool_name, config, reasons, runner_type=module_active)
    if result.ui_request_exit:
        con_host.print(Text('  [!] QUITING UPON USER REQUEST', style='bold red'))
        raise SystemExit(1)
    if result.ui_request_editcnf:
        config_editor.display_banner()
        config_editor.run_editor(str(Path(local_config_dir, relative_path)))
    else:
        result.runner.cmdgen()

@cli_host.command('version', help='Shows Program Banner & Version, Then Exits.')
def showv():
    """Print the full banner for the configured release.

    Read `script_version` from local metadata and exit with status 0 after rendering the
    Mark IV banner.
    """

    main_config = load_main_config()
    ProgBanner(main_config.dictionary['script_data']['script_version']).display_banner()

    raise SystemExit(0)

@cli_host.command('update', help='Update APT Dependencies Or Check For Newer Version Of The ASADT MK 4 Script')
def hostupdate(apt_dep_update: bool = False):
    """Check release metadata or install the configured APT packages.

    With apt_dep_update=True, validate APT_DEP.dependency_list and delegate the root
    check and installation to ProgUpdate.localdebupdate. Otherwise, an empty
    script_master disables release checks. When configured, compare the downloaded
    version with the local identifier and ask before saving the release archive.
    """

    main_config = load_main_config()
    ProgBanner(main_config.dictionary['script_data']['script_version']).display_banner('short')

    if apt_dep_update == True:

        apt_config = main_config.dictionary.get('APT_DEP')
        packages = apt_config.get('dependency_list') if isinstance(apt_config, dict) else None
        try:
            ProgUpdate.localdebupdate(packages=packages)
        except ValueError as error:
            con_host.print(Text(f'scriptinfo.toml: {error}', style='bold red'))
            raise SystemExit(3) from error

        raise SystemExit(0)

    if not main_config.dictionary['script_data']['script_master']:

        print('[yellow bold]  [!] Release Updates Are Not Configured For This ASADT Checkout.')
        raise SystemExit(0)

    updateobj = ProgUpdate(main_config.dictionary['script_data']['script_version'], main_config.dictionary['script_data']['script_master'])
    updateobj.check_rfs()
    new_hsi = TOML_Loader(local_config_dir).parceldecode(BytesIO(updateobj.updatecap.content))
    if not new_hsi.status_ok:
        run_error(f'Invalid release metadata: {new_hsi.status_data}')

    remote_version = new_hsi.dictionary['script_data']['script_version']
    if not updateobj.verify_update_requirements(remote_version):
        raise SystemExit(0)
    if Prompt.ask('\n[yellow bold]  [?] Answer? (Y/N)').lower() != 'y':
        print('[red bold]\n  [!] Exiting Upon Users Request!\n')
        raise SystemExit(1)
    updateobj.new_release_download(main_config.dictionary['script_data']['script_repo'], str(remote_version).lower())

if __name__ == '__main__':

    cli_host()
