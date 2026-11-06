# 📚 ASADT4 code reference

## 🧭 Follow a run through the code

1. `asadt.asadtexec` resolves the module and tool, loads its TOML and validates the configuration. `--target` selects terminal input. Opening a form loads Qt on demand.
2. Both interfaces start with `initial_values(tool, config)`. Integer keys identify fields across the model, widgets, verifier and command builder. For example, Nmap field 1 holds the port expression. A combo box yields a one-element list, a checkbox yields a boolean, and a spin box yields an integer.
3. `ScanTool` and `HackTool` share runner preparation. `ArgVerify` works on a copy and associates correctable errors with field keys. The interface handles repair and confirmation. Directory creation can happen here, before command execution.
4. `build_command()` returns an argv list. `cmdgen()` executes it and exits with the child status. `RunCommand` maps a launch or report I/O error to 127. The GUI and terminal both use the same report-path helpers.

### Which checks run when ArgVerify is disabled?

| Module | When its rules apply |
| --- | --- |
| [`tool_config.py`](../libasadt4/tool_config.py) | After `TOML_Loader` parses the file, the CLI validates the tool settings. Both interfaces use `initial_values` to combine model defaults with TOML overrides. The form validates per-run configuration edits again on submission. |
| [`privileges.py`](../libasadt4/privileges.py) | The CLI asks about Nmap options that may require elevation before opening the form or preparing a terminal runner. On submission, the form checks for additional requirements introduced by edits. The user can choose to proceed with current permissions. |
| [`output_paths.py`](../libasadt4/output_paths.py) | The preview and command builder share report naming rules. With verification enabled, `ArgVerify.input_verification()` calls `prepare_tool_output`. With verification disabled, the CLI or form calls it directly. Each interface checks for existing reports at submission. |

For example, with Nmap's `-oA` format, the command builder passes one basename to Nmap. The output helpers expand that basename to `.nmap`, `.xml` and `.gnmap` for preview and overwrite confirmation. Turning off hostname or NSE validation still leaves all three destinations covered.

### Inspect a command without launching the scanner

Run this from the checkout with its Python requirements installed. It uses an existing temporary directory, the shipped Nmap configuration, and the built-in NSE category expression.

```python
from tempfile import TemporaryDirectory

from libasadt4.mainprog import TOML_Loader
from libasadt4.modules_main import ScanTool
from libasadt4.gui_models import OUTPUT_KEYS
from libasadt4.tool_config import initial_values

loaded = TOML_Loader("config").loadfile("scantool/nmap.toml")
if not loaded.status_ok:
    raise ValueError(loaded.status_data)

config = loaded.dictionary
with TemporaryDirectory() as directory:
    values = initial_values("nmap", config)
    values.update({0: "127.0.0.1", 1: "80,443", OUTPUT_KEYS["nmap"]: directory})
    scan = ScanTool("nmap", config, values)
    print(scan.build_command())
```

### Read a failure at the right layer

| Signal | Where to handle it |
| --- | --- |
| `TOML_Loader.status_ok == False` | Read `status_data` for the underlying I/O or parser error. The CLI exits with 4 for unreadable main metadata and 3 for invalid tool configuration. |
| `ArgumentIssue` | Use the integer `key` to identify an editable field in `TOOL_MODELS`. |
| `VerificationFailed` | Runner preparation stopped. Its exit code is 3. A field error is available through `issue` when applicable. |
| Child exit status | `RunCommand` returns it and the runner's `cmdgen()` raises `SystemExit` with it. For Nmap, a failed preliminary step stops the main scan. |

## 🔎 Symbol index

Each entry links to its definition. Signatures below omit the bound instance or class parameter. Local callbacks appear under their enclosing function.

- [CLI](#cli)
- [Field models](#field-models)
- [Configuration and defaults](#configuration-and-defaults)
- [Desktop forms](#desktop-forms)
- [Argument verification and execution](#argument-verification-and-execution)
- [Report destinations](#report-destinations)
- [Privilege diagnostics](#privilege-diagnostics)
- [Metadata, editor and updates](#metadata-editor-and-updates)
- [Regression suite](#regression-suite)

## CLI

[Source module](../asadt.py)

#### [`load_main_config()`](../asadt.py#L56)

Load the release metadata used by the CLI. Resolve `config/scriptinfo.toml` beside the entry point. Return the populated `TOML_Loader` or print its diagnostic and exit with status 4.

#### [`cnfedit()`](../asadt.py#L69)

Choose a saved TOML file in the terminal editor. Number the files recursively under the checkout's config directory before parsing any of them, so malformed files can still be repaired. Choosing a file delegates to `CnfEdit.run_editor`. Quitting returns to the caller.

#### [`resolve_tool(name, tool)`](../asadt.py#L92)

Resolve a tool selection to a module and tool name. Return a `(module, tool)` pair for a qualified name or a unique short name. An unknown or ambiguous selection exits through `run_error`.

#### [`run_error(message)`](../asadt.py#L111)

End an invalid CLI invocation with status 3. Print `message` as literal Rich text so user input cannot alter the diagnostic's formatting.

#### [`confirm_run(question, **prompt_options)`](../asadt.py#L121)

Ask for permission to continue a terminal operation. Forward `prompt_options` to Typer and default to No. Return a boolean, treating EOF, interruption and an aborted prompt as refusal.

#### [`prepare_terminal_run(runner_type, tool, config, values, debugger, *, verify=True)`](../asadt.py#L133)

Construct the selected runner and handle correctable field errors. Use `runner_type(tool, config, values, ...)` to verify the submission. On a TTY, an accepted repair updates the rejected field or radio group and retries. With verification off, still check output paths and prompt before creating directories.

#### [`terminal_values(tool, config, target, output_dir, ports, resolvers, script=None)`](../asadt.py#L183)

Convert terminal options to the same integer-keyed values used by Qt. Start with TOML and model defaults. Store an absolute output directory, map each supported switch to its field, and exit with status 3 for missing Nmap ports, missing MassDNS resolvers or incompatible options.

#### [`asadtexec(module_name=None, tool_name=None, debugger=False, target=None, output_dir=None, ports=None, resolvers=None, script=None, no_argverify=False)`](../asadt.py#L223)

Dispatch the Typer `run` command. With no tool, print the registry. A tool name opens Qt unless `target` selects terminal execution. Load and validate its TOML before dispatch, ask about privileges and overwrites, and propagate the runner's exit status.

#### [`showv()`](../asadt.py#L325)

Print the full banner for the configured release. Read `script_version` from local metadata and exit with status 0 after rendering the Mark IV banner.

#### [`hostupdate(apt_dep_update=False)`](../asadt.py#L338)

Check release metadata or install the configured APT dependencies. The APT route validates package names and requires root. The release route exits cleanly when disabled. When configured, fetch and parse metadata, compare version strings, and ask before downloading an archive.


## Field models

[Source module](../libasadt4/gui_models.py)

#### [`field(setting, label, help_text, *, kind='Input', section='Options', **options)`](../libasadt4/gui_models.py#L567)

Build a field descriptor for the reconnaissance tool registry. Combine the TOML setting, UI label, help text, kind and section with tool-specific options. Text inputs receive the native-argument validation flag.

#### [`target(setting, label, example, **options)`](../libasadt4/gui_models.py#L577)

Define a required field in the Target section. Use `example` as field help and forward options such as `input_file` to the shared descriptor factory.

#### [`switch(setting, label, help_text, default=False)`](../libasadt4/gui_models.py#L586)

Describe a boolean tool option for a checkbox. Store the setting name, label, help and initial checked state. The form and terminal defaults consume the same record.

#### [`limit(setting, label, help_text, maximum)`](../libasadt4/gui_models.py#L595)

Describe a bounded integer tool option. Set an inclusive range from zero through `maximum`. The zero default lets the command builder omit the corresponding native limit.


## Configuration and defaults

[Source module](../libasadt4/tool_config.py)

#### [`configured_report_filename(tool, config)`](../libasadt4/tool_config.py#L27)

Resolve the report basename for a scanner. Nmap and Nikto require a filename in their output settings. Nmap rejects percent signs throughout the output path. Read the tool's key from `ScriptOutput`, falling back to JSON for DNSRecon and WPScan or text for other tools. Reject empty names, directory components, dot entries and NUL with `ValueError`.

#### [`dnsrecon_output_filename(config)`](../libasadt4/tool_config.py#L46)

Return the configured DNSRecon report basename. Delegate to the common filename validator with the DNSRecon key. The output path builder applies the run's selected format later.

#### [`output_formats(tool, rules)`](../libasadt4/tool_config.py#L55)

List native output format identifiers for Nmap or Nikto. Return a tuple suitable for both validation and the form. Nmap uses its native output switches. Nikto's legacy profile also permits `nbe`.

#### [`enabled(value)`](../libasadt4/tool_config.py#L67)

Interpret a supported TOML boolean representation. Return a boolean for native booleans or the exact legacy strings `'True'` and `'False'`. Raise `ValueError` for other values.

#### [`ArgumentIssue(ValueError)`](../libasadt4/tool_config.py#L80)

Associate a validation failure with an editable field. The exception text is suitable for the user. Its integer `key` lets a terminal or Qt caller offer a correction for the same field.

#### [`ArgumentIssue.__init__(key, message)`](../libasadt4/tool_config.py#L87)

Attach the field key to its diagnostic. Pass `message` to `ValueError` and store `key` for focus, selection or retry.

#### [`missing_required_fields(tool, values)`](../libasadt4/tool_config.py#L97)

Find unfilled required fields in display order. Use the tool's required keys against the submitted mapping or sequence. Return model records for absent, false-like or whitespace-only values.

#### [`validate_field(field, value)`](../libasadt4/tool_config.py#L116)

Check a scalar value against its field model. Validate checkbox booleans, integer limits, choice membership, native input strings and absolute Nikto root paths as applicable. Raise `ValueError` with the reason.

#### [`normalize_slider(field, value)`](../libasadt4/tool_config.py#L140)

Convert legacy slider numbers into validated integers. Older fields accept an in-range numeric value that can be truncated. New settings require an integer. Return the validated value or raise `ValueError`.

#### [`validated_defaults(tool, config)`](../libasadt4/tool_config.py#L159)

Check the optional TOML defaults against the tool's settings. Return the defaults table or an empty mapping. Unknown keys and invalid values raise `ValueError` identifying the setting.

#### [`initial_values(tool, config)`](../libasadt4/tool_config.py#L179)

Build the shared starting values for terminal and Qt submissions. Return a fresh integer-keyed dictionary using validated TOML overrides and model defaults. Wrap combo choices in one-element lists and initialize Nikto's cookie switch from its profile.

#### [`validate_tool_config(tool, config)`](../libasadt4/tool_config.py#L206)

Validate the tool's TOML before showing a form or starting a run. Check enablers, defaults and report settings. Nmap and Nikto have format-specific rules, including Nikto profile and display codes. Raise `ValueError` on an invalid setting.

#### [`validate_packages(packages)`](../libasadt4/tool_config.py#L245)

Validate the dependency list before it reaches APT. Require a nonempty list of package names matching the allowed Debian-style spelling. Reject option-like entries and trailing removal operators with `ValueError`.


## Desktop forms

[Source module](../libasadt4/displayboxhandler.py)

#### [`ToolDialog(QDialog)`](../libasadt4/displayboxhandler.py#L29)

Edit one tool submission in a modal Qt form. Fields are keyed by the integer indices in `TOOL_MODELS`. Runtime edits affect a private configuration copy. The service consumes the final action (`quit`, `edit` or `execute`), collected values and optional prepared runner.

#### [`ToolDialog.__init__(toolname, parent=None, config=None, acknowledged=(), debug=None, *, runner_type=None)`](../libasadt4/displayboxhandler.py#L37)

Build the form and connect model fields to their widgets. Use `toolname` to select sections, defaults, output controls and runtime settings. Copy `config`, retain acknowledged privilege warnings, and use optional `debug` and `runner_type` callbacks during submission.

#### [`ToolDialog.add_section(section)`](../libasadt4/displayboxhandler.py#L149)

Create a scrollable section and its navigation entry. Append the page to the stacked widget and return its `QFormLayout` for the caller to populate.

#### [`ToolDialog.add_runtime_settings(form)`](../libasadt4/displayboxhandler.py#L176)

Bind the per-run configuration controls to the dialog's TOML copy. Build enablers and tool-specific report or profile controls in `form`. Connect filename and format changes to the output preview.

#### [`ToolDialog.add_runtime_settings.refresh_formats()`](../libasadt4/displayboxhandler.py#L210)

Synchronize Nikto report formats after a profile change. Add the legacy `nbe` choice when supported and remove it for the current profile. The combo box updates its bound setting when its selection changes.

#### [`ToolDialog.add_config_input(form, table, key, label, choices=())`](../libasadt4/displayboxhandler.py#L226)

Add a control that writes directly to a runtime setting. Create a combo for `choices` or a line edit for text. Connect its change signal to `table[key]`, label it and return the widget.

#### [`ToolDialog.paintEvent(event)`](../libasadt4/displayboxhandler.py#L245)

Render the dialog and trace its first visible layout. Delegate `event` to Qt. When tracing is enabled, log the first section, window size and pixel ratio once.

#### [`ToolDialog.add_field(form, field)`](../libasadt4/displayboxhandler.py#L258)

Create and register a Qt control for one model field. Use the field key for lookup, apply defaults and tooltips, and wire the appropriate radio group, file picker or paired slider. The registered control supplies the submitted value.

#### [`ToolDialog.add_field.browse_file()`](../libasadt4/displayboxhandler.py#L327)

Pick a file for this text field. Start from the current field text and copy the chosen path into the widget. Cancelling preserves the current value.

#### [`ToolDialog.refresh_msfpc_fields()`](../libasadt4/displayboxhandler.py#L345)

Enable the radio groups used by the selected output mode. Loop disables single-payload groups. Batch retains the console choice. Disabling a group preserves its selections for a later switch back.

#### [`ToolDialog.refresh_dns_threads()`](../libasadt4/displayboxhandler.py#L358)

Apply DNSRecon's mode restriction to the worker control. Enable field 7 only for a mode listed in `DNS_THREADED_MODES`. The command builder applies the corresponding restriction to argv.

#### [`ToolDialog.browse_directory(target)`](../libasadt4/displayboxhandler.py#L366)

Select an output directory for a line edit. Pass the existing text as the picker's starting path and replace it only after the user selects a directory.

#### [`ToolDialog.collect_values()`](../libasadt4/displayboxhandler.py#L377)

Read the widgets into a fresh submission dictionary. Use integer model keys. Return stripped text, integer spin values, single-item lists for combos and booleans for checkable controls.

#### [`ToolDialog.trace_submission(values)`](../libasadt4/displayboxhandler.py#L396)

Trace the captured form values and editable runtime settings. Render designated sensitive values as `<redacted>`. Include the backing settings for visible configuration controls before argument normalization.

#### [`ToolDialog.refresh_output_preview()`](../libasadt4/displayboxhandler.py#L415)

Describe prospective output files in the form. Resolve filenames from current widgets and config, inspect the selected directory, and display collisions, access errors or MSFPC's naming pattern without creating reports.

#### [`ToolDialog.show_field_error(key, title, message)`](../libasadt4/displayboxhandler.py#L455)

Bring a rejected field into view for correction. Find the field's section by key, scroll to its widget, show the diagnostic and focus the control. Select existing text in line edits.

#### [`ToolDialog.request_execute()`](../libasadt4/displayboxhandler.py#L472)

Validate the submission and accept the form when ready. Check runtime settings, required fields, privilege warnings, report paths and overwrites. Prepare a runner when supplied. On rejection keep the form open. On success, store the runner and set the execute action.

#### [`ToolDialog.request_execute.confirm_create(directory)`](../libasadt4/displayboxhandler.py#L510)

Ask whether the form may create a missing directory. Return true only for an explicit Yes. The output helper creates the directory after this callback returns.

#### [`ToolDialog.confirm_overwrite(values)`](../libasadt4/displayboxhandler.py#L549)

Recheck collisions when the user submits the form. Return true when no question is needed or the user approves the current overwrite list. The confirmation defaults to No.

#### [`ToolDialog.privilege_warning(values)`](../libasadt4/displayboxhandler.py#L563)

Describe privilege requirements added by the current form settings. Filter the reasons against those acknowledged before opening the form. Return an empty string if no additional warning applies.

#### [`ToolDialog.request_edit()`](../libasadt4/displayboxhandler.py#L574)

Hand off the saved TOML file to the terminal editor. Set the action to `edit` and accept the dialog. The CLI opens the file after the modal event loop returns.

#### [`ToolDialog.window_style()`](../libasadt4/displayboxhandler.py#L585)

Return the Qt stylesheet for the tool form. Supply a QSS string shared by the dialog's fields, navigation, buttons and scroll controls, using the red and black palette.

#### [`DisplayBoxHandler_Service`](../libasadt4/displayboxhandler.py#L623)

Expose the modal Qt form through the existing service interface. Call `DISPLAY_UI_MODEL` with a registered tool, then inspect `event`, `values`, `config` and the edit/exit flags. CLI callers also receive the runner prepared during submission.

#### [`DisplayBoxHandler_Service.__init__(debug=None)`](../libasadt4/displayboxhandler.py#L633)

Initialize the shared Qt application and the service result fields. Reuse an existing application if available. Select Qt dialogs on Wayland, use the available Adwaita theme when appropriate, and report platform details through the optional debug callback.

#### [`DisplayBoxHandler_Service.DISPLAY_UI_MODEL(displayboxid, config=None, acknowledged=(), *, runner_type=None)`](../libasadt4/displayboxhandler.py#L660)

Run a tool dialog and copy its result onto this service. Reject an unknown ID with `ValueError`. After the modal loop, record field values, config, runner, verification state and action flags, schedule deletion of the dialog, and return the service.


## Argument verification and execution

[Source module](../libasadt4/modules_main.py)

#### [`print_debug(message)`](../libasadt4/modules_main.py#L39)

Write a diagnostic to the debug console. Split multiline text and prefix each line with the debug marker so command arguments and trace events remain readable on stderr.

#### [`gui_console(debug)`](../libasadt4/modules_main.py#L49)

Select the Rich console used during GUI activity. Use the debug console when tracing and both streams are interactive so Rich can redraw its spinner. Otherwise use the normal console.

#### [`apply_argument_defaults(tool, args, config, trace=None)`](../libasadt4/modules_main.py#L60)

Backfill fields introduced after the original argument layout. Update the supplied dictionary or append contiguous missing list entries in model order. Read TOML overrides, wrap list choices and normalize checkbox defaults. An optional trace reports each inserted field.

#### [`VerificationFailed(SystemExit)`](../libasadt4/modules_main.py#L89)

Signal a failed runner preparation with exit status 3. Carry the verifier's issue so interactive callers can focus a field or offer a retry. The issue can be absent after a declined directory prompt.

#### [`VerificationFailed.__init__(issue)`](../libasadt4/modules_main.py#L96)

Capture the failure reported by the verifier. Set the `SystemExit` code to 3 and expose `issue` to the Qt and terminal handlers.

#### [`ArgVerify`](../libasadt4/modules_main.py#L106)

Validate submitted tool fields and prepare a working copy. Preserve the original field container in `preagverify`. Read normalized fields from `argstoverify` after `input_verification()` succeeds. Validation may resolve hostnames, read local files and request an output directory.

#### [`ArgVerify.__init__(args, vparam, rules, *, debug=False)`](../libasadt4/modules_main.py#L114)

Snapshot the input container and initialize the validation state. Copy a dictionary or convert a sequence to a list, then make a second shallow copy for normalization. Store the tool name, configuration and debug setting.

#### [`ArgVerify._trace(message)`](../libasadt4/modules_main.py#L129)

Report a verification step when debug mode is active. Prefix the message with the tool name and dispatch it to the shared debug console.

#### [`ArgVerify._confirm_create(directory)`](../libasadt4/modules_main.py#L138)

Ask whether the terminal run may create an output directory. Show the proposed directory and return true for a Y response. EOF and keyboard interruption count as refusal.

#### [`ArgVerify._ip_literal(value)`](../libasadt4/modules_main.py#L152)

Parse an IPv4 or IPv6 literal and validate any interface scope. Return the parsed address object or raise `ValueError`. Scoped IPv6 suffixes accept word characters, dots and hyphens.

#### [`ArgVerify._host(value)`](../libasadt4/modules_main.py#L166)

Validate an IP literal or DNS hostname. Check address-looking strings as literals. Convert DNS names to IDNA and enforce label syntax and length. This syntax check performs no DNS lookup.

#### [`ArgVerify._number(text, low, high)`](../libasadt4/modules_main.py#L185)

Parse decimal digits within inclusive bounds. Return the integer or raise `ValueError` naming the accepted range. Signs and whitespace are rejected.

#### [`ArgVerify._numeric_range(text, low, high, *, open_ends=False)`](../libasadt4/modules_main.py#L195)

Validate a number or ascending hyphenated range. Apply the inclusive bounds to each endpoint. When `open_ends` is enabled, omitted endpoints take the corresponding bound.

#### [`ArgVerify._nmap_target(value)`](../libasadt4/modules_main.py#L210)

Validate an Nmap target in the requested address family. Accept IP addresses, hostname targets, CIDR prefixes and IPv4 octet ranges. Resolve hostnames using the submitted IPv6 switch and raise `ValueError` on lookup or syntax failure.

#### [`ArgVerify._nmap_ports(value)`](../libasadt4/modules_main.py#L249)

Validate comma-separated Nmap port or protocol selectors. Track protocol qualifiers and bracketed lists, accept native service masks, and check numeric ranges. IP protocol numbers use an upper bound of 255.

#### [`ArgVerify._single_port(value)`](../libasadt4/modules_main.py#L276)

Validate one decimal transport port. Use the inclusive range 1 through 65535 and propagate a range or syntax error to the field validator.

#### [`ArgVerify._nikto_ports(value)`](../libasadt4/modules_main.py#L284)

Check a Nikto port list. Split comma-separated entries, trim whitespace and require a port or closed ascending range from 1 through 65535.

#### [`ArgVerify._endpoint(value)`](../libasadt4/modules_main.py#L293)

Validate the host and optional port of a URL or authority. Handle bare and bracketed IPv6 as well as hostnames. Reject malformed authorities, whitespace and zero ports with a generic diagnostic that omits credentials.

#### [`ArgVerify._nikto_target(value)`](../libasadt4/modules_main.py#L316)

Classify a Nikto target before deeper validation. Accept the stdin marker and existing file paths directly. Validate other inputs as endpoints. A later check reads host-list files.

#### [`ArgVerify._proxies(value)`](../libasadt4/modules_main.py#L326)

Validate an Nmap proxy chain. Split the comma-separated value and check each endpoint in order. The first invalid authority raises a credential-free error.

#### [`ArgVerify._nameservers(value)`](../libasadt4/modules_main.py#L335)

Check each DNS server supplied for a DNSRecon run. Split the comma-separated setting and validate each trimmed entry as a hostname or address literal.

#### [`ArgVerify._msfpc_address(value)`](../libasadt4/modules_main.py#L344)

Check an MSFPC address or local interface name. Permit short interface identifiers containing underscores and validate remaining inputs with the host checker.

#### [`ArgVerify._verify_msfpc_setup()`](../libasadt4/modules_main.py#L355)

Check the controls active in the selected MSFPC mode. Loop uses only its mode selection. Batch also checks the console. Single output enforces payload-format, stage, direction, transport and console compatibility with field-keyed errors.

#### [`ArgVerify._verify_msfpc_setup.selected(keys, label, *, optional=False)`](../libasadt4/modules_main.py#L364)

Read one radio-group selection from the captured field values. Require boolean values and exactly one checked key unless the group is optional. Return the selected key or `None`. Attach the relevant key to any `ArgumentIssue`.

#### [`ArgVerify._dns_query_name(value)`](../libasadt4/modules_main.py#L417)

Validate one query name from a domain list. Accept the DNS root, IDNA names and an optional leading wildcard. Reject malformed labels or an overlong encoded name with `ValueError`.

#### [`ArgVerify._massdns_resolver(value)`](../libasadt4/modules_main.py#L432)

Validate one MassDNS resolver list entry. Accept address literals and bracketed IPv6 with an optional port. Reject scope suffixes and require explicit ports from 1 through 65534.

#### [`ArgVerify._nikto_list_entry(value)`](../libasadt4/modules_main.py#L454)

Validate one Nikto host-list record. Support Nmap grepable host records, URLs, address literals and host/port lists. Route each address and port through the same range checks as the terminal form.

#### [`ArgVerify._verify_list_file(key, check_entry=None)`](../libasadt4/modules_main.py#L484)

Validate the file in a submitted field one record at a time. Skip blank lines and comments, reject binary controls, and apply the optional entry checker to UTF-8 records. Report the field and line number for invalid entries and require at least one usable record.

#### [`ArgVerify._verify_tool_inputs()`](../libasadt4/modules_main.py#L516)

Apply checks specific to the selected tool's input format. Inspect MassDNS lists, optional DIRB/dnsmap wordlists and Nikto host files, or enforce MSFPC output combinations. Failures retain the field key for interactive correction.

#### [`ArgVerify._verify_network_fields()`](../libasadt4/modules_main.py#L536)

Dispatch address and port checks by tool and field key. Require text without control characters, validate nonempty values, and convert missing or invalid fields to labeled `ArgumentIssue` exceptions.

#### [`ArgVerify._script_directories()`](../libasadt4/modules_main.py#L574)

Locate candidate Nmap scripts directories in search order. Use `NMAPDIR`, per-user data, executable-relative and system paths as applicable, followed by the working directory. Return deduplicated candidate paths.

#### [`ArgVerify._selector_names(expression)`](../libasadt4/modules_main.py#L600)

Yield operands from an NSE boolean expression. Track parentheses and the position of unary and binary operators. Raise `ValueError` on a misplaced token, unbalanced group or unfinished expression during iteration.

#### [`ArgVerify._script_path(rule, directories)`](../libasadt4/modules_main.py#L628)

Check whether an NSE operand names a local script or directory. Probe the supplied search directories. Accept regular files, implicit `.nse` suffixes and directory paths with a trailing separator.

#### [`ArgVerify.verify_nse_selector(selector)`](../libasadt4/modules_main.py#L644)

Validate comma-separated NSE selectors against local data. Recognize paths, categories, boolean expressions, script names and star patterns. Read the first available `scripts/script.db` and raise `ValueError` for invalid syntax or unverifiable names.

#### [`ArgVerify._validate_fields()`](../libasadt4/modules_main.py#L687)

Check required entries and normalize model-backed values. Run network checks, then normalize sliders and checkbox representations in the working copy. Validate choice and input settings and associate failures with their field keys.

#### [`ArgVerify.input_verification(confirm_create=None, *, console=None)`](../libasadt4/modules_main.py#L728)

Run the verification pipeline and return this verifier. Apply defaults, validate fields and tool inputs, resolve NSE selectors, and prepare output paths via an optional creation callback. Inspect `requires_exit` and `issue` before consuming normalized arguments.

#### [`ToolModule`](../libasadt4/modules_main.py#L778)

Prepare shared execution state for scanners and MSFPC. Subclasses build argv from `execute_arguments` and `execute_properties`. Construction copies inputs, applies defaults and optionally verifies them before a command can run.

#### [`ToolModule.__init__(toolname, config_rules, exec_args, show_debug=False, ioverify=True, *, confirm_create=None)`](../libasadt4/modules_main.py#L786)

Prepare one tool submission for command construction. Store the selected tool, config and debug settings. With verification on, raise `VerificationFailed` on a rejected submission. With it off, copy fields and fill legacy defaults.

#### [`ToolModule.trace_step(step)`](../libasadt4/modules_main.py#L815)

Mark the beginning of one runner step. When debugging, include the concrete runner class and tool name. Emitting at entry keeps failures in preliminary commands visible.

#### [`ScanTool(ToolModule)`](../libasadt4/modules_main.py#L825)

Build and run commands for the registered scanners. Use `build_command()` to inspect argv and `cmdgen()` to execute. Nmap may run preliminary commands. Assetfinder captures stdout as its report.

#### [`ScanTool.cmdgen()`](../libasadt4/modules_main.py#L835)

Execute a scan and exit with its native status. Run Nmap's configured database update and traceroute in order before the main scan. Stop at the first failure. Route assetfinder stdout through staged report replacement.

#### [`ScanTool.nmap_limits()`](../libasadt4/modules_main.py#L864)

Build Nmap's optional timeout and rate arguments. Use field 17 as minutes per host and field 18 as a maximum packet rate. Return a list of tokens shared by traceroute and the main scan.

#### [`ScanTool.build_command()`](../libasadt4/modules_main.py#L878)

Translate a scanner submission into native argv. Read the prepared fields and config, select the correct flags and report path, and return a list ready for subprocess execution. An unknown or disabled scanner exits with status 1.

#### [`HackTool(ToolModule)`](../libasadt4/modules_main.py#L1014)

Build and run MSFPC for the submitted output mode. Keep command construction separate from execution. MSFPC selects output filenames and runs with its working directory set to the selected destination.

#### [`HackTool.cmdgen()`](../libasadt4/modules_main.py#L1023)

Execute MSFPC in the requested output directory. Build argv and pass field 27 as the child process's working directory. Exit with the returned status, leaving the parent process's working directory intact.

#### [`HackTool.build_command()`](../libasadt4/modules_main.py#L1036)

Translate single, loop or batch fields to MSFPC argv. Select only the positional arguments active for the mode and append `verbose` when configured. An unknown or disabled tool exits with status 1.

#### [`run_to_report(command, cwd, report)`](../libasadt4/modules_main.py#L1074)

Capture a subprocess's stdout beside the final report. Run `command` in `cwd`, replace the destination after status 0 and remove the temporary file on other paths. Return the child status or propagate an OS error.

#### [`RunCommand(command, cwd=None, *, debug=False, stdout_path=None)`](../libasadt4/modules_main.py#L1092)

Launch a native argument list and return its exit code. Optionally set the working directory or capture stdout in a report. Debug tracing redacts values after designated sensitive flags and records timing. OS errors map to status 127.


## Report destinations

[Source module](../libasadt4/output_paths.py)

#### [`check_writable(path, directory=False)`](../libasadt4/output_paths.py#L10)

Check whether the process can write at a destination. For a directory, require write and traversal access. For a file, check the existing file or its parent if new. Raise `PermissionError` with the absolute path.

#### [`report_path(tool, values, config)`](../libasadt4/output_paths.py#L27)

Build the output argument for a scanner. Read the directory from the tool's output field and join it with the configured filename. DNSRecon derives the extension from its selected format. For Nmap `oA`, the returned string is the basename.

#### [`report_files(tool, values, config)`](../libasadt4/output_paths.py#L50)

List the concrete files a scanner could overwrite. Return `Path` objects. Expand Nmap `oA` into three suffixes. Return an empty list for MSFPC's runtime filenames or when Nmap/Nikto report configuration is unavailable.

#### [`check_tool_output(tool, values, config)`](../libasadt4/output_paths.py#L65)

Verify access to the report directory and each known destination. Use `report_files` to expand multi-format output before testing writability. Propagate filesystem failures to the terminal or Qt caller.

#### [`overwrite_question(tool, values, config)`](../libasadt4/output_paths.py#L76)

Describe the overwrite decision for this submission. Return a question listing existing reports, or a directory warning for MSFPC when nonempty. Return `None` when no confirmation is needed.

#### [`prepare_tool_output(tool, values, config, confirm_create)`](../libasadt4/output_paths.py#L95)

Prepare the output directory and check report destinations. For reconnaissance tools, reject unreadable input files or a report aliasing an input. Ask `confirm_create(Path)` before creating directories. Return false on refusal, true on success, and propagate field or filesystem errors.


## Privilege diagnostics

[Source module](../libasadt4/privileges.py)

#### [`script_permissions(script)`](../libasadt4/privileges.py#L11)

Describe the script's filesystem access and the process's privilege level. Return a diagnostic string with the absolute path, mode and access flags when available. Use the effective UID on POSIX or the administrator check on Windows.

#### [`privilege_reasons(tool, config, values=None)`](../libasadt4/privileges.py#L36)

Identify Nmap options that may need additional privileges. Return a list of reasons for a non-root POSIX run. Check access to the NSE database, configured discovery and scan method, and raw-packet options when submitted values are available.

#### [`privilege_message(reasons)`](../libasadt4/privileges.py#L74)

Format privilege reasons for an interactive Nmap launch. Join the reason strings with newlines and append the checkout-specific sudo invocation. The caller decides whether to prompt.


## Metadata, editor and updates

[Source module](../libasadt4/mainprog.py)

#### [`TOML_Loader`](../libasadt4/mainprog.py#L27)

Parse configuration into a reusable result object. Both entry points return the loader. Inspect `status_ok` before reading `dictionary`. On failure the dictionary is cleared and `status_data` holds the original exception.

#### [`TOML_Loader.__init__(configuration_directory)`](../libasadt4/mainprog.py#L35)

Select the base directory for file-backed TOML reads. Store `configuration_directory` for subsequent calls to `loadfile`. Parsing begins when a file or stream is supplied.

#### [`TOML_Loader.loadfile(file_id)`](../libasadt4/mainprog.py#L44)

Load a binary TOML file relative to the configured base directory. Record the filename, parsed dictionary and status on this loader. File and parse failures are recorded in `status_data`. Return the loader on either path.

#### [`TOML_Loader.parceldecode(binary_data)`](../libasadt4/mainprog.py#L72)

Parse TOML from a caller-supplied binary stream. Consume and close the stream using its context manager. Replace the previous result and return this loader with the parsed dictionary or captured failure.

#### [`CnfEdit`](../libasadt4/mainprog.py#L100)

Launch a terminal editor for persistent configuration changes. The CLI and GUI use this launcher with a starting line and optional read-only mode. It delegates editing to an installed program and propagates the editor's exit status.

#### [`CnfEdit.__init__(start_line, editor_type='nano', user_fileperm=False, read_only=False)`](../libasadt4/mainprog.py#L108)

Set editor preferences for later file opens. Retain the starting line, preferred editor, read-only flag and legacy permission-change opt-in. The default writable path preserves the original mode.

#### [`CnfEdit.display_banner()`](../libasadt4/mainprog.py#L122)

Identify the configuration editor in the console. Print a Rich panel independently of TOML parsing so a user can still open and repair an invalid configuration.

#### [`CnfEdit.run_editor(file_to_edit)`](../libasadt4/mainprog.py#L130)

Open the supplied file in the first available editor. Check writability for edits, prefer nano or Vim, and try fallbacks on missing executables. Exit with the editor status or 1 on a launch/access failure. The optional legacy chmod applies only after a successful writable edit.

#### [`ProgBanner`](../libasadt4/mainprog.py#L168)

Render the CLI's short or full Mark IV banner. Construct with the release identifier from local metadata. The full form includes the developer credit, while the short form can identify a debug session.

#### [`ProgBanner.__init__(current_version)`](../libasadt4/mainprog.py#L175)

Prepare the two Rich banner strings for this version. Embed `current_version` in the short banner and escape its centered release label in the full banner footer.

#### [`ProgBanner.display_banner(banner_type='normal', *, debugger=False)`](../libasadt4/mainprog.py#L197)

Print the requested banner variant. Use `normal` for the full artwork or `short` for the compact header. The optional debug marker applies to the short header.

#### [`ProgUpdate`](../libasadt4/mainprog.py#L215)

Fetch release metadata and archives or install Linux dependencies. Construction requests the metadata URL with a timeout. Release operations use the working directory. The separate class-level APT entry point validates package names and checks privileges.

#### [`ProgUpdate.__init__(current_hsv, update_target)`](../libasadt4/mainprog.py#L223)

Fetch metadata for comparison with the locally configured version. Store the current version and HTTP response. The CLI parses the response in memory. The GET uses a 30-second timeout and can raise a requests exception.

#### [`ProgUpdate.write_uf()`](../libasadt4/mainprog.py#L236)

For file-backed callers, write metadata inside a private temporary directory for this updater and expose the relative path in `newversion_config`.

#### [`ProgUpdate.save_download(filename, response)`](../libasadt4/mainprog.py#L246)

Write an HTTP response through a temporary sibling file. Stream 512 KiB chunks, replace the destination after the write completes, and clean up staging. Propagate request errors and exit with status 1 on filesystem errors.

#### [`ProgUpdate.remove_uf()`](../libasadt4/mainprog.py#L272)

Release the private temporary directory allocated by `write_uf()`. Repeated cleanup calls are safe.

#### [`ProgUpdate.check_rfs()`](../libasadt4/mainprog.py#L285)

Check the metadata response before parsing it. Call the response's `raise_for_status()` so an unsuccessful HTTP status propagates to the caller.

#### [`ProgUpdate.verify_update_requirements(new_hsv)`](../libasadt4/mainprog.py#L294)

Compare the remote release string with the local identifier. Print the outcome and return true when the identifiers differ. The comparison uses exact string equality, including case, without ordering semantic versions.

#### [`ProgUpdate.new_release_download(release_url, release_id)`](../libasadt4/mainprog.py#L321)

Download the selected ASADT4 release archive. Append `/<release_id>.zip` to the base URL, check the HTTP status, and save the response as `ASADT4_<release_id>.zip` in the current directory.

#### [`ProgUpdate.localdebupdate(toolbox_main=None, *, packages=None)`](../libasadt4/mainprog.py#L339)

Install validated dependency packages on an elevated Linux host. Accept the configured package list or the legacy tool registry. Run `apt update` followed by `apt install -y` only on success. Propagate APT failure status and reject non-root execution.


## Regression suite

[Source module](../tests/test_regressions.py)

#### [`RegressionTests(unittest.TestCase)`](../tests/test_regressions.py#L25)

Exercise the CLI, Qt forms, validation and tool runners together. Use a shared offscreen Qt application and per-test temporary directories. Subprocess and HTTP doubles cover command construction and failure handling.

#### [`RegressionTests.setUpClass()`](../tests/test_regressions.py#L33)

Initialize Qt once for the test class. Retain a service instance so widgets and dialogs can share the same application across cases.

#### [`RegressionTests.tearDownClass()`](../tests/test_regressions.py#L42)

Flush deferred Qt deletions at class teardown. Send pending deferred-delete events after the last test using the shared application.

#### [`RegressionTests.setUp()`](../tests/test_regressions.py#L50)

Allocate an isolated output directory for each test. Register cleanup with unittest so report and configuration fixtures are removed after the case.

#### [`RegressionTests.form(name, config=None)`](../tests/test_regressions.py#L59)

Construct a test dialog with optional tool configuration. Return the dialog and register explicit Qt object deletion with the test's cleanup stack.

#### [`RegressionTests.massdns_inputs()`](../tests/test_regressions.py#L69)

Create a minimal domain list and resolver list. Write one valid record to each temporary file and return their string paths in submission order.

#### [`RegressionTests.module(name, edits=None, verify=True)`](../tests/test_regressions.py#L80)

Prepare a real runner backed by isolated field values. Collect form defaults, supply a local target and output path, overlay edits and load the selected tool's TOML. Return a scanner or MSFPC runner using the requested verification mode.

#### [`RegressionTests.test_gui_value_contract_and_defaults()`](../tests/test_regressions.py#L100)

Check the field-key contract of the original forms. Compare contiguous key sets and representative Nmap, Nikto and MSFPC defaults.

#### [`RegressionTests.test_slider_drag_and_numeric_entry_share_the_submitted_value()`](../tests/test_regressions.py#L115)

Check paired slider and spin-box controls. Change each control in turn and compare widget ranges, displayed values and the final integer submission.

#### [`RegressionTests.test_radio_groups_and_single_output_reset()`](../tests/test_regressions.py#L139)

Exercise mutually exclusive form choices. Switch out of MSFPC loop mode and change transport to verify that the previous radio selection clears.

#### [`RegressionTests.test_required_fields_keep_dialog_open()`](../tests/test_regressions.py#L153)

Submit a form with missing required values. Verify that the warning appears once and the form keeps its initial action.

#### [`RegressionTests.test_execute_and_edit_actions()`](../tests/test_regressions.py#L165)

Distinguish a submitted form from an edit request. Check the service-facing action after a valid run request and after choosing the TOML editor.

#### [`RegressionTests.test_service_close_and_edit_flags_reset()`](../tests/test_regressions.py#L180)

Reuse a GUI service across successive dialogs. Schedule each close action on Qt's event loop and check that edit and exit flags reflect only the latest dialog.

#### [`RegressionTests.test_service_close_and_edit_flags_reset.finish()`](../tests/test_regressions.py#L187)

Close the active modal dialog for this case. Invoke the selected edit or reject action from a timer while the service's modal event loop is running.

#### [`RegressionTests.test_every_registered_tool_has_gui_and_config()`](../tests/test_regressions.py#L201)

Check registry, field model and configuration coverage. For each tool, construct its dialog and runner, check the required output field, and build native argv.

#### [`RegressionTests.test_nikto_ssl_can_return_to_automatic()`](../tests/test_regressions.py#L215)

Exercise Nikto's automatic SSL choice. Return the radio group to automatic and check that both override fields clear and argv omits both switches.

#### [`RegressionTests.test_recon_toml_options_reach_native_commands()`](../tests/test_regressions.py#L231)

Check reconnaissance settings end to end. Load configured values, submit each form, compare report previews and native argv, and exercise disabled tools.

#### [`RegressionTests.test_assetfinder_publishes_stdout_only_after_success()`](../tests/test_regressions.py#L276)

Check staged assetfinder report writes. Simulate successful and failed subprocesses, checking report contents, exit status and cleanup of temporary siblings.

#### [`RegressionTests.test_assetfinder_publishes_stdout_only_after_success.run(command, cwd, stdout)`](../tests/test_regressions.py#L285)

Simulate an assetfinder subprocess writing to its stdout stream. Check the expected native command, write the fixture bytes and return the status selected by the surrounding case.

#### [`RegressionTests.test_runtime_fields_are_local_to_each_tool_dialog()`](../tests/test_regressions.py#L301)

Check the lifetime of runtime TOML edits. Toggle an enabler and compare the active form, original settings and a freshly opened dialog.

#### [`RegressionTests.test_nikto_runtime_validation_and_legacy_profile()`](../tests/test_regressions.py#L322)

Check Nikto's profile-specific runtime controls. Switch profiles to inspect the legacy report choice, then submit invalid display codes and verify focus returns to runtime settings.

#### [`RegressionTests.test_gui_debug_lines_clear_and_redraw_the_spinner()`](../tests/test_regressions.py#L346)

Check interactive Rich rendering during a debug run. Capture terminal control sequences and verify that the spinner redraws after stderr diagnostics.

#### [`RegressionTests.test_run_uses_runtime_config_for_preview_and_command()`](../tests/test_regressions.py#L371)

Use a single Nmap configuration for preview and execution. Change runtime report settings, compare emitted argv and diagnostic order, and check the saved TOML bytes.

#### [`RegressionTests.test_run_uses_runtime_config_for_preview_and_command.fill_form()`](../tests/test_regressions.py#L383)

Populate the active Nmap dialog during CLI dispatch. Edit runtime report settings and capture the preview before submitting the form to the mocked runner.

#### [`RegressionTests.test_gui_output_directory_creation_and_errors()`](../tests/test_regressions.py#L420)

Exercise directory creation through the Qt submit action. Simulate refusal, approval and a filesystem error and check both dialog state and directory existence.

#### [`RegressionTests.test_gui_opt_out_and_debug_redaction()`](../tests/test_regressions.py#L456)

Exercise a GUI run with ArgVerify disabled. Check that credentials reach the mocked tool, are redacted from diagnostics, and a fresh dialog starts with verification enabled.

#### [`RegressionTests.test_gui_opt_out_and_debug_redaction.fill_form()`](../tests/test_regressions.py#L465)

Submit sensitive Nikto fields with ArgVerify disabled. Drive the active modal form so the test can compare redacted diagnostics with actual subprocess arguments.

#### [`RegressionTests.test_overwrite_rechecks_all_formats_at_submit()`](../tests/test_regressions.py#L493)

Create Nmap report collisions after the initial preview. Check the confirmation lists only existing `oA` outputs, then exercise refusal and acceptance.

#### [`RegressionTests.test_msfpc_warns_for_nonempty_directory()`](../tests/test_regressions.py#L521)

Check the overwrite prompt for MSFPC's dynamic filenames. Submit a populated directory and verify that a declined confirmation identifies the directory and keeps the form open.

#### [`RegressionTests.test_nmap_privilege_warning_matches_request(uid)`](../tests/test_regressions.py#L538)

Check privilege warnings against the active Nmap settings. Simulate privilege levels and database access, then change the scan method to inspect which warnings remain.

#### [`RegressionTests.test_nmap_preliminary_failures_stop_execution()`](../tests/test_regressions.py#L575)

Propagate a failed Nmap preliminary step. Supply exit codes for the mocked database update and traceroute and count launches before the runner exits.

#### [`RegressionTests.test_dnsrecon_modes_formats_and_optional_arguments()`](../tests/test_regressions.py#L589)

Check DNSRecon's native command across output modes. Compare form defaults and subprocess argv, including optional DNS settings and the reported child status.

#### [`RegressionTests.test_directory_preview_and_format_changes()`](../tests/test_regressions.py#L616)

Refresh a report preview as the destination changes. Exercise missing, empty and populated directories, then change DNSRecon's format and check the displayed filename.

#### [`RegressionTests.test_nmap_all_formats_preview()`](../tests/test_regressions.py#L639)

Expand Nmap's all-formats basename in the GUI. Check the three planned report paths against the configured basename and selected directory.

#### [`RegressionTests.test_dnsrecon_required_fields_and_disabled_tool()`](../tests/test_regressions.py#L652)

Reject incomplete and disabled DNSRecon runs. Check exit codes 3 and 1 respectively and verify that a disabled tool never reaches execution.

#### [`RegressionTests.test_nmap_zero_timing_and_spaced_output()`](../tests/test_regressions.py#L670)

Preserve Nmap's zero timing and literal report path. Inspect the command for `-T0`, the selected scan mode and a single output argument containing spaces.

#### [`RegressionTests.test_all_scan_methods()`](../tests/test_regressions.py#L683)

Map every Nmap scan choice to its native switch. Build argv for each displayed method and check the corresponding flag.

#### [`RegressionTests.test_nmap_limits_and_script_file_without_tracing()`](../tests/test_regressions.py#L696)

Separate Nmap resource limits, NSE arguments and trace flags. Check shared limits in traceroute and the main scan, then toggle NSE to verify script-file handling.

#### [`RegressionTests.test_legacy_argument_containers_pick_up_defaults()`](../tests/test_regressions.py#L717)

Prepare original-width inputs with newer TOML defaults. Check the resulting rate and timeout arguments while preserving the caller's original 17 fields.

#### [`RegressionTests.test_nikto_profile_and_scan_options()`](../tests/test_regressions.py#L733)

Check profile-specific cookie switches and scan limits. Build current and legacy commands, inspect application paths and time units, and reject incompatible output formats.

#### [`RegressionTests.test_dns_defaults_and_per_run_overrides()`](../tests/test_regressions.py#L758)

Exercise DNSRecon defaults and dialog overrides together. Compare preview filenames, thread availability and generated argv across modes, then inspect the original configuration.

#### [`RegressionTests.test_msfpc_mode_changes_preserve_inactive_values()`](../tests/test_regressions.py#L791)

Switch between single, batch and loop output. Check which controls remain enabled, then restore single mode and verify the prior transport selection.

#### [`RegressionTests.test_bad_tool_settings_stop_before_gui()`](../tests/test_regressions.py#L810)

Reject malformed tool configuration before Qt initialization. Supply invalid settings and check that status 3 names the TOML file and key without opening a form.

#### [`RegressionTests.test_apt_uses_configured_packages_and_rejects_arguments()`](../tests/test_regressions.py#L835)

Validate APT inputs at the CLI boundary. Compare install argv with the configured list and reject invalid package entries before subprocess invocation.

#### [`RegressionTests.test_nikto_disabled_is_not_truthy_string()`](../tests/test_regressions.py#L859)

Exercise the legacy string representation of a disabled Nikto tool. Set its enable flag to the string false representation and check the runner exits with status 1.

#### [`RegressionTests.test_nikto_useragent_has_value()`](../tests/test_regressions.py#L871)

Preserve a custom Nikto user agent as a native argument. Locate `-useragent` and check that its next token holds the full configured value.

#### [`RegressionTests.test_msfpc_loop_uses_address_and_port()`](../tests/test_regressions.py#L880)

Check the positional arguments for MSFPC loop mode. Compare the entire generated command with the submitted address and port in order.

#### [`RegressionTests.test_msfpc_default_and_batch()`](../tests/test_regressions.py#L889)

Compare MSFPC's default and batch command layouts. Build both modes from form values and check each argument list against the expected wrapper syntax.

#### [`RegressionTests.test_msfpc_checks_only_options_used_in_selected_mode()`](../tests/test_regressions.py#L900)

Check MSFPC's mode-dependent validation. Verify accepted combinations, the field key reported for invalid single-output options, and handling of inactive controls in loop or batch.

#### [`RegressionTests.test_list_verification_points_to_the_file_and_line()`](../tests/test_regressions.py#L920)

Validate list-file failures and recovery. Supply malformed records, check their field and line diagnostics before output creation, then retry with corrected input.

#### [`RegressionTests.test_shell_metacharacters_remain_one_argument()`](../tests/test_regressions.py#L954)

Exercise literal argument boundaries with shell metacharacters. Check the verified rejection path and inspect the argv passed to a mocked subprocess when bypassing verification.

#### [`RegressionTests.test_execution_return_code_and_cwd()`](../tests/test_regressions.py#L972)

Check child status and working-directory isolation. Return status 7 from the mock process and compare its output directory with the parent process's original working directory.

#### [`RegressionTests.test_missing_executable()`](../tests/test_regressions.py#L987)

Map a missing tool to the runner's launch-error status. Make subprocess launch raise `FileNotFoundError` and expect status 127.

#### [`RegressionTests.test_debug_mode_without_verification()`](../tests/test_regressions.py#L996)

Check execution tracing with input verification disabled. Compare credential-bearing argv against the redacted trace and check timing, working directory and exit status.

#### [`RegressionTests.test_input_snapshot_is_not_mutated()`](../tests/test_regressions.py#L1016)

Preserve raw fields while applying Nmap's default selector. Compare the blank original input with the prepared `not intrusive` expression.

#### [`RegressionTests.test_verification_trace_normalization_failures_and_privacy()`](../tests/test_regressions.py#L1026)

Inspect debug output across verification outcomes. Exercise default filling, slider normalization, invalid inputs and bypass mode, and check that sensitive values stay out of the trace.

#### [`RegressionTests.test_verification_trace_normalization_failures_and_privacy.verify(**options)`](../tests/test_regressions.py#L1036)

Construct the runner with the enclosing test's values and trace options. Pass the supplied keyword options into the runner so the same submission can exercise verified and bypassed paths.

#### [`RegressionTests.test_invalid_slider_stops_before_output_prompt()`](../tests/test_regressions.py#L1063)

Reject invalid numeric input before preparing output. Check the labeled diagnostic, exit status, missing directory and unused creation prompt.

#### [`RegressionTests.test_legacy_sliders_normalize_without_changing_input()`](../tests/test_regressions.py#L1081)

Preserve original numeric values during legacy slider conversion. Compare the input snapshot to the normalized integer and check status 3 for an invalid input.

#### [`RegressionTests.test_gui_and_direct_call_report_same_required_fields()`](../tests/test_regressions.py#L1096)

Compare required-field diagnostics across entry points. Submit identical missing values to Qt and the verifier and compare their user-facing messages.

#### [`RegressionTests.test_directory_creation_failure_stops_execution()`](../tests/test_regressions.py#L1114)

Surface a failed directory creation during verification. Approve a missing directory but simulate a permission error from mkdir and inspect the verifier's exit flag.

#### [`RegressionTests.test_config_editor_preserves_path_and_permissions()`](../tests/test_regressions.py#L1128)

Check the default writable editor invocation. Verify the file path remains one argv token, nano starts at the requested line and chmod is never called.

#### [`RegressionTests.test_cnfedit_banner_picker_and_missing_editor_fallback()`](../tests/test_regressions.py#L1142)

Exercise the public configuration editor from the CLI. Select a listed file, simulate a missing preferred editor, and check fallback argv and the propagated editor status.

#### [`RegressionTests.test_read_only_report_and_directory_keep_form_open()`](../tests/test_regressions.py#L1164)

Exercise output permission failures as an unprivileged user. Use read-only report and directory fixtures to check the diagnostic, retained report and rejected submission.

#### [`RegressionTests.test_read_only_config_and_download()`](../tests/test_regressions.py#L1191)

Exercise protected files for editing and downloads. Check that viewing can launch, writable editing is refused, and a failed download preserves the existing file.

#### [`RegressionTests.test_toml_errors_are_reported()`](../tests/test_regressions.py#L1213)

Record missing and malformed TOML as failed loader results. Read both fixtures and check `status_ok` after each attempt.

#### [`RegressionTests.test_download_preserves_previous_file_on_write_failure()`](../tests/test_regressions.py#L1223)

Check atomic replacement and cleanup for downloads. Fail the final replacement, verify the prior bytes and absence of staging files, then allow a successful retry.

#### [`RegressionTests.test_apt_update_requires_root_before_launch(uid, call)`](../tests/test_regressions.py#L1244)

Check privilege gating and legacy APT registry support. Simulate non-root and root UIDs and inspect the ordered update/install subprocess calls.

#### [`RegressionTests.test_update_http_has_timeout()`](../tests/test_regressions.py#L1260)

Check the timeout on release metadata fetches. Mock the HTTP client and verify a single GET to the fixture URL with a 30-second timeout.

#### [`RegressionTests.test_terminal_prompt_precedes_gui_and_covers_only_acknowledged_options(uid)`](../tests/test_regressions.py#L1271)

Carry privilege decisions from the CLI into the form. Decline before GUI creation, then accept and enable another privileged option to verify it receives a separate warning.

#### [`RegressionTests.test_cli_runs_outside_checkout_without_gui()`](../tests/test_regressions.py#L1299)

Launch the CLI from a different working directory. Check command statuses, the configured release in the Mark IV banner and the alignment of its frame.

#### [`RegressionTests.test_run_lists_tools_and_opens_form_by_short_name()`](../tests/test_regressions.py#L1318)

Check discovery and short-name dispatch. List all tools and individual modules without Qt, then verify that a short name opens the expected form.

#### [`RegressionTests.test_run_target_reaches_every_tool_with_form_defaults()`](../tests/test_regressions.py#L1340)

Exercise terminal dispatch for every registered tool. Compare mocked native commands with the expected default form commands and ensure Qt stays unopened.

#### [`RegressionTests.test_terminal_nmap_script_expression()`](../tests/test_regressions.py#L1375)

Preserve a terminal NSE expression as a single token. Submit the expression through Typer and inspect the argument immediately after `--script`.

#### [`RegressionTests.test_nse_names_against_local_catalog()`](../tests/test_regressions.py#L1394)

Resolve NSE selectors against a fixture script catalog. Exercise known names, paths, categories and invalid selectors, checking the failure occurs before output creation or launch.

#### [`RegressionTests.test_verified_network_fields()`](../tests/test_regressions.py#L1425)

Check address and port rules across tool models. Use valid and malformed submissions for the affected tools, building commands on success and expecting status 3 for rejected fields.

#### [`RegressionTests.test_unavailable_nse_catalog_explains_how_to_verify_names()`](../tests/test_regressions.py#L1453)

Identify the recovery path for missing NSE data. Hide script directories and verify that the diagnostic for an unverifiable name identifies `NMAPDIR`.

#### [`RegressionTests.test_nmap_checks_hostname_resolution_before_launch()`](../tests/test_regressions.py#L1464)

Check DNS lookup failure and address-family selection. Mock resolution for both families, verify failure precedes output creation and confirm the IPv6 selector uses the requested family.

#### [`RegressionTests.test_no_argverify_applies_to_one_target_run()`](../tests/test_regressions.py#L1493)

Limit verification bypass to one terminal submission. Check directory creation and overwrite refusal during bypass, then verify a later normal submission checks the hostname again.

#### [`RegressionTests.test_invalid_network_fields_stop_terminal_run()`](../tests/test_regressions.py#L1526)

Reject invalid terminal address fields before launch. Inspect the field label, exit status and untouched output directory, and assert the runner never executes.

#### [`RegressionTests.test_gui_can_correct_rejected_field_and_keep_other_values()`](../tests/test_regressions.py#L1547)

Recover from an invalid NSE expression in the form. Inspect the focused field, fix the selector, resubmit, and check the runner retains the original target and ports.

#### [`RegressionTests.test_interactive_terminal_repairs_or_cancels()`](../tests/test_regressions.py#L1578)

Exercise argument correction on an interactive input stream. Supply scripted refusals, EOF and retries. Check that only a valid replacement port launches the command with the original target.

#### [`RegressionTests.test_interactive_terminal_repairs_or_cancels.Terminal(StringIO)`](../tests/test_regressions.py#L1585)

Present a scripted input buffer as an interactive terminal. Use `StringIO` responses to exercise the CLI's correction branch without an actual terminal.

#### [`RegressionTests.test_interactive_terminal_repairs_or_cancels.Terminal.isatty()`](../tests/test_regressions.py#L1591)

Advertise the fixture stream as a TTY. Return true so the runner offers interactive field repair.

#### [`RegressionTests.test_run_terminal_validation_overwrite_and_exit_status()`](../tests/test_regressions.py#L1615)

Check CLI validation and overwrite confirmation for reports. Try invalid combinations, decline and accept overwrites, and verify file preservation and child status propagation.

#### [`RegressionTests.test_terminal_run_stops_when_confirmation_is_unavailable()`](../tests/test_regressions.py#L1656)

Exercise EOF at directory and privilege prompts. Check cancellation statuses, directory existence and lack of subprocess execution.
