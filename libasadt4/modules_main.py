"""Validate tool submissions, build native argument lists and execute commands.

ToolModule prepares the arguments submitted by the CLI or Qt form. With
verification enabled, construction calls ArgVerify.input_verification, which
can resolve hostnames, read input files and create the output directory.
ScanTool.build_command and HackTool.build_command return the main command as
a list of strings. Their cmdgen methods execute the command sequence and
raise SystemExit with the final status, including zero on success.

To add a scanner, register its name in ScanTool.submodules, supply its field
model in gui_models and its TOML under config/scantool/, then implement its
argv branch in ScanTool.build_command. The CLI uses the registry for discovery
and config lookup. The Qt service uses TOOL_MODELS for discovery. A tool needs
both registrations. For tools using RECON_FIELDS, tool_config derives the
enable switch and output_paths supplies the default report naming convention.

Positional submissions, Qt widgets, terminal_values and command builders all
use the same integer field keys. Preserve existing keys when adding an option. In
RECON_FIELDS, list order assigns the keys, including an automatically appended
output directory. Inserting an option ahead of that directory shifts its key.
The regression suite in tests/test_regressions.py compares model defaults,
submitted values, native arguments and report paths using mocked subprocesses.
"""

scantool_module_version = 'v4.0.1'
hacktool_module_version = 'v4.0.1'
MSFPC_FORMATS = ('apk', 'asp', 'aspx', 'sh', 'jsp', 'elf', 'macho', 'pl', 'php', 'ps1', 'py', 'war', 'windows')

try:

    from rich.console import Console

    con_host = Console()
    debug_console = Console(stderr=True, markup=False, highlight=False, soft_wrap=True)

    from rich.text import Text
    from rich.prompt import Prompt
    from rich import print

    import os
    import re
    import shutil
    import socket
    import subprocess
    import tempfile
    import time
    from fnmatch import fnmatchcase
    from ipaddress import ip_address
    from pathlib import Path
    from urllib.parse import urlsplit
    from libasadt4.output_paths import prepare_tool_output, report_path
    from libasadt4.gui_models import DNS_THREADED_MODES, OUTPUT_KEYS, TOOL_MODELS
    from libasadt4.tool_config import ArgumentIssue, enabled, missing_required_fields, normalize_slider, validate_field

except ImportError as ErrorID:

    print(f'Python Submodule Import Error > "modules_main" Module Failed To Import, Cannot Proceed!\nReason > {ErrorID}')

    raise SystemExit(4)

def print_debug(message: str):
    """Write a diagnostic to the debug console.

    Split multiline text and prefix each line with the debug marker so command arguments
    and trace events remain readable on stderr.
    """
    for line in message.splitlines():
        debug_console.print(f'  [debug] {line}', style='orange1')


def gui_console(debug):
    """Select the Rich console used during GUI activity.

    Use the debug console when tracing and both streams are interactive so Rich can
    redraw its spinner. Otherwise use the normal console.
    """
    if debug and con_host.is_interactive and debug_console.is_interactive:
        return debug_console
    return con_host


def apply_argument_defaults(tool, args, config, trace=None):
    """Fill missing setting-backed fields in a mutable submission.

    For a dictionary, insert each absent field by key. For a list, append only the next
    contiguous key in model order. Existing values take precedence over TOML defaults,
    which take precedence over model defaults. Wrap choices in one-element lists and
    normalize checkbox defaults with enabled(). The optional trace callback receives the
    label of each inserted field.
    """
    for field in TOOL_MODELS.get(tool, ()):
        if 'setting' not in field:
            continue
        key = field['key']
        if isinstance(args, dict) and key in args:
            continue
        if isinstance(args, list) and key != len(args):
            continue
        fallback = field['choices'][0] if field['kind'] == 'Listbox' else field.get('default_value', '')
        value = (config or {}).get('Defaults', {}).get(field['setting'], fallback)
        if field['kind'] == 'Listbox':
            value = [value]
        elif field['kind'] == 'Checkbox':
            value = enabled(value)
        if isinstance(args, list):
            args.append(value)
        else:
            args[key] = value
        if trace:
            trace(f"{field['label']}: applied default")


class VerificationFailed(SystemExit):
    """Runner preparation failed with exit status 3.

    The issue attribute holds the underlying exception. An ArgumentIssue identifies the
    integer field key that the caller can use to focus a widget or prompt for a
    replacement. Other exceptions apply to the submission as a whole. Declining
    directory creation leaves issue set to None.

    Catch VerificationFailed around runner construction to offer a retry. It derives
    from SystemExit, so noninteractive callers can propagate the status and handlers for
    Exception alone will let it pass.
    """

    def __init__(self, issue):
        """Capture the failure reported by the verifier.

        Set the `SystemExit` code to 3 and expose `issue` to the Qt and terminal
        handlers.
        """
        super().__init__(3)
        self.issue = issue


class ArgVerify:
    """Validate a single tool submission and prepare its execution arguments.

    preagverify holds a shallow snapshot of the submitted values. argstoverify is a
    second shallow copy used for defaults and normalization. Replace a field when
    normalizing a nested choice list to preserve the snapshot. verificationparam selects
    the field model and rulelist holds the tool configuration. Callers validate that
    configuration with tool_config.validate_tool_config before constructing a runner.

    input_verification returns the verifier. Check requires_exit and issue before using
    argstoverify. Verification can resolve a hostname, read input files and create an
    output directory with the caller's consent.

    Use tool_config.validate_field or normalize_slider for scalar model constraints.
    Register address and port parsers in _verify_network_fields, which associates a
    parser's ValueError with the field key. Put cross-field and file-content checks in
    _verify_tool_inputs. For line-oriented inputs, _verify_list_file adds the field
    label and line number to a record checker's error. Both interfaces display these
    messages, so diagnostics should identify the field without including credentials.
    """

    def __init__(self, args: dict | list | tuple, vparam: str, rules: dict | None, *, debug=False):
        """Snapshot the input container and initialize the validation state.

        Copy a dictionary or convert a sequence to a list, then make a second shallow
        copy for normalization. Store the tool name, configuration and debug setting.
        """
        self.preagverify = args.copy() if isinstance(args, dict) else list(args)
        self.argstoverify = self.preagverify.copy()
        self.rulelist = rules
        self.verificationparam = vparam
        self.requires_exit = False
        self.issue = None
        self.debug = debug

    def _trace(self, message):
        """Report a verification step when debug mode is active.

        Prefix the message with the tool name and dispatch it to the shared debug
        console.
        """
        if self.debug:
            print_debug(f'ArgVerify ({self.verificationparam}): {message}')

    def _confirm_create(self, directory):
        """Ask whether the terminal run may create an output directory.

        Show the proposed directory and return true for a Y response. EOF and keyboard
        interruption count as refusal.
        """
        self._trace('output directory missing, requesting permission to create it')
        con_host.print(Text(f'  Output directory "{directory}" does not exist.', style='bold yellow'))
        try:
            return Prompt.ask('Create the output directory? (y/N)').lower() == 'y'
        except (EOFError, KeyboardInterrupt):
            return False

    @staticmethod
    def _ip_literal(value):
        """Parse an IPv4 or IPv6 literal and validate any interface scope.

        Return the parsed address object or raise `ValueError`. Scoped IPv6 suffixes
        accept word characters, dots and hyphens.
        """
        try:
            address = ip_address(value)
        except ValueError:
            raise ValueError('enter a valid IPv4 or IPv6 address') from None
        if '%' in value and not re.fullmatch(r'[\w.-]+', value.partition('%')[2]):
            raise ValueError('enter a valid IPv6 interface scope')
        return address

    def _host(self, value):
        """Validate the syntax of an IP literal or DNS hostname.

        Parse strings containing a colon or consisting of digits and dots as IP
        literals. For hostnames, encode labels with IDNA and enforce DNS length and
        character limits. Nmap target verification performs address resolution
        separately.
        """
        if ':' in value or re.fullmatch(r'[0-9.]+', value):
            self._ip_literal(value)
            return
        try:
            name = value.removesuffix('.').encode('idna').decode('ascii')
        except UnicodeError:
            raise ValueError('enter a valid hostname') from None
        label = r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        if len(name) > 253 or not all(re.fullmatch(label, part) for part in name.split('.')):
            raise ValueError('enter a valid hostname or IP address')

    @staticmethod
    def _number(text, low, high):
        """Parse decimal digits within inclusive bounds.

        Return the integer or raise `ValueError` naming the accepted range. Signs and
        whitespace are rejected.
        """
        if not re.fullmatch(r'[0-9]+', text) or not low <= int(text) <= high:
            raise ValueError(f'expected a number from {low} to {high}')
        return int(text)

    def _numeric_range(self, text, low, high, *, open_ends=False):
        """Validate a number or ascending hyphenated range.

        Apply the inclusive bounds to each endpoint. When `open_ends` is enabled,
        omitted endpoints take the corresponding bound.
        """
        start, dash, end = text.partition('-')
        if not dash:
            self._number(text, low, high)
            return
        first = low if open_ends and not start else self._number(start, low, high)
        last = high if open_ends and not end else self._number(end, low, high)
        if first > last:
            raise ValueError('range start exceeds range end')

    def _nmap_target(self, value):
        """Validate an Nmap target in the requested address family.

        Accept IP addresses, hostname targets, CIDR prefixes and IPv4 octet ranges.
        Resolve hostnames using the submitted IPv6 switch and raise `ValueError` on
        lookup or syntax failure.
        """
        target, slash, prefix = value.partition('/')
        hostname = False
        if target.startswith('-'):
            raise ValueError('enter a target without a leading dash')
        if re.fullmatch(r'[0-9.,*-]+', target) and any(c in target for c in ',-*'):
            octets = target.split('.')
            if len(octets) != 4:
                raise ValueError('an IPv4 octet range needs four octets')
            for octet in octets:
                if octet != '*':
                    for item in octet.split(','):
                        self._numeric_range(item, 0, 255, open_ends=True)
            prefix_max = 32
        else:
            self._host(target)
            is_ipv4 = re.fullmatch(r'[0-9.]+', target)
            hostname = ':' not in target and not is_ipv4
            prefix_max = 128 if ':' in target or (self.argstoverify[5] and not is_ipv4) else 32
        if slash:
            self._number(prefix, 0, prefix_max)
        if hostname:
            family = socket.AF_INET6 if self.argstoverify[5] else socket.AF_INET
            version = 'IPv6' if family == socket.AF_INET6 else 'IPv4'
            try:
                addresses = socket.getaddrinfo(target, None, family, socket.SOCK_STREAM)
            except socket.gaierror as error:
                raise ValueError(f'Could not resolve {target!r} to an {version} address: {error.strerror or error}. '
                                 'Check the name or enter an IP address.') from error
            if not addresses:
                raise ValueError(f'No {version} address found for {target!r}. Check the name or enter an IP address.')
            self._trace(f'Nmap target {target!r} resolved to {addresses[0][4][0]}')

    def _nmap_ports(self, value):
        """Validate comma-separated Nmap port or protocol selectors.

        Track protocol qualifiers and bracketed lists, accept native service masks, and
        check numeric ranges. IP protocol numbers use an upper bound of 255.
        """
        high = 65535
        bracket = False
        for item in value.split(','):
            item = item.strip()
            qualifier = re.match(r'^([TUSP]):', item)
            if qualifier:
                high = 255 if qualifier[1] == 'P' else 65535
                item = item[2:]
            if item.startswith('[') and not bracket:
                bracket = True
                item = item[1:]
            if item.endswith(']') and bracket:
                bracket = False
                item = item[:-1]
            # Nmap resolves service names and masks using its own services file.
            if not re.fullmatch(r'[a-z*?][a-zA-Z0-9_.*?-]*', item):
                self._numeric_range(item, 0, high, open_ends=True)
        if bracket:
            raise ValueError('missing closing bracket in port list')

    def _single_port(self, value):
        """Validate one decimal transport port.

        Use the inclusive range 1 through 65535 and propagate a range or syntax error to
        the field validator.
        """
        self._number(value, 1, 65535)

    def _nikto_ports(self, value):
        """Check a Nikto port list.

        Split comma-separated entries, trim whitespace and require a port or closed
        ascending range from 1 through 65535.
        """
        for item in value.split(','):
            self._numeric_range(item.strip(), 1, 65535)

    def _endpoint(self, value):
        """Validate the host and optional port of a URL or authority.

        Handle bare and bracketed IPv6 as well as hostnames. Reject malformed
        authorities, whitespace and zero ports with a generic diagnostic that omits
        credentials.
        """
        if '://' not in value and value.count(':') > 1 and not value.startswith('['):
            self._ip_literal(value)
            return
        try:
            parts = urlsplit(value if '://' in value else '//' + value)
            authority = parts.netloc.rsplit('@', 1)[-1]
            if not parts.hostname or authority.endswith(':') or any(c.isspace() for c in value):
                raise ValueError
            if authority.startswith('[') and not re.fullmatch(r'\[[^]]+\](?::[0-9]+)?', authority):
                raise ValueError
            self._host(parts.hostname)
            if parts.port == 0:
                raise ValueError
        except ValueError:
            raise ValueError('enter a valid host or URL with an optional port from 1 to 65535') from None

    def _nikto_target(self, value):
        """Classify a Nikto target before deeper validation.

        Accept the stdin marker and existing file paths directly. Validate other inputs
        as endpoints. A later check reads host-list files.
        """
        # Nikto also accepts an existing file of target hosts.
        if value != '-' and not Path(value).is_file():
            self._endpoint(value)

    def _proxies(self, value):
        """Validate an Nmap proxy chain.

        Split the comma-separated value and check each endpoint in order. The first
        invalid authority raises a credential-free error.
        """
        for item in value.split(','):
            self._endpoint(item)

    def _nameservers(self, value):
        """Check each DNS server supplied for a DNSRecon run.

        Split the comma-separated setting and validate each trimmed entry as a hostname
        or address literal.
        """
        for item in value.split(','):
            self._host(item.strip())

    def _msfpc_address(self, value):
        """Check an MSFPC address or local interface name.

        Permit short interface identifiers containing underscores and validate remaining
        inputs with the host checker.
        """
        # Local interfaces may include underscores, unlike DNS hostnames.
        if '_' in value and re.fullmatch(r'[a-zA-Z][\w.-]{0,14}', value):
            return
        self._host(value)

    def _verify_msfpc_setup(self):
        """Validate radio selections used by the active MSFPC mode.

        Loop requires only a valid mode selection here. Batch also requires one console
        choice. Single-output mode checks format, console, stage, direction and
        transport together. An incompatible combination raises ArgumentIssue with an
        editable field key. Address and port checks run separately for all modes.
        """
        args = self.argstoverify

        def selected(keys, label, *, optional=False):
            """Read one radio-group selection from the captured field values.

            Require boolean values and exactly one checked key unless the group is
            optional. Return the selected key or `None`. Attach the relevant key to any
            `ArgumentIssue`.
            """
            choices = []
            for key in keys:
                try:
                    value = args[key]
                except (IndexError, KeyError):
                    raise ArgumentIssue(key, f'{label}: missing selection') from None
                if type(value) is not bool:
                    raise ArgumentIssue(key, f'{label}: expected a radio-button selection')
                if value:
                    choices.append(key)
            if len(choices) > 1 or (not choices and not optional):
                raise ArgumentIssue(keys[0], f'{label}: select one option')
            return choices[0] if choices else None

        mode = selected((25, 26), 'Output mode', optional=True)
        if mode == 25:
            return
        console = selected((10, 11), 'Console')
        if mode == 26:
            return
        fmt = MSFPC_FORMATS[selected(range(12, 25), 'Payload format') - 12]
        bind = selected((2, 3), 'Connection direction') == 2
        staged = selected((4, 5), 'Payload stage') == 4
        method = selected(range(6, 10), 'Transport')
        meterpreter = console == 11
        if bind and method != 6:
            raise ArgumentIssue(6, 'MSFPC bind connections require TCP. Choose TCP or switch to reverse.')
        if fmt in ('sh', 'pl'):
            direction = 'reverse TCP' if fmt == 'sh' else 'TCP'
            for invalid, key in ((meterpreter, 10), (not staged, 4), (method != 6, 6), (fmt == 'sh' and bind, 3)):
                if invalid:
                    raise ArgumentIssue(key, f'For {fmt}, choose Command Shell, Staged, and {direction}.')
        if fmt == 'macho' and (staged or meterpreter):
            raise ArgumentIssue(5 if staged else 10, 'For macOS, choose Stageless and Command Shell.')
        if fmt == 'php' and not meterpreter:
            raise ArgumentIssue(11, 'For PHP, choose Meterpreter.')
        if fmt in ('asp', 'jsp', 'elf', 'py', 'war') and meterpreter and not staged:
            raise ArgumentIssue(4, f'For {fmt} with Meterpreter, choose Staged.')
        if fmt == 'py' and staged and not meterpreter:
            raise ArgumentIssue(5, 'For Python with Command Shell, choose Stageless.')
        if fmt in ('py', 'war') and not staged and bind:
            raise ArgumentIssue(3, f'MSFPC {fmt} requires reverse when using stageless.')
        if fmt == 'war' and method == 9:
            raise ArgumentIssue(6, 'MSFPC WAR does not support find_port. Choose another transport.')

    @staticmethod
    def _dns_query_name(value):
        """Validate one query name from a domain list.

        Accept the DNS root, IDNA names and an optional leading wildcard. Reject
        malformed labels or an overlong encoded name with `ValueError`.
        """
        if value == '.':
            return
        try:
            name = value.removesuffix('.').encode('idna').decode('ascii')
        except UnicodeError:
            raise ValueError('invalid DNS query name') from None
        if len(name) > 253 or not re.fullmatch(r'(?:\*\.)?[\w-]+(?:\.[\w-]+)*', name, re.ASCII):
            raise ValueError('expected one DNS name per line')

    def _massdns_resolver(self, value):
        """Validate one MassDNS resolver list entry.

        Accept address literals and bracketed IPv6 with an optional port. Reject scope
        suffixes and require explicit ports from 1 through 65534.
        """
        if value.startswith('['):
            match = re.fullmatch(r'\[([^\]]+)\](?::([0-9]+))?', value)
            if not match or ':' not in match[1]:
                raise ValueError('expected [IPv6] or [IPv6]:port')
            address, port = match.groups()
        elif value.count(':') == 1:
            address, port = value.split(':')
        else:
            address, port = value, None
        self._ip_literal(address)
        if '%' in address:
            raise ValueError('MassDNS needs an IP literal without a scope suffix')
        if port is not None:
            # MassDNS str_to_addr rejects explicit ports >= UINT16_MAX.
            self._number(port, 1, 65534)

    def _nikto_list_entry(self, value):
        """Validate one Nikto host-list record.

        Support Nmap grepable host records, URLs, address literals and host/port lists.
        Route each address and port through the same range checks as the terminal form.
        """
        if value.startswith('Host:'):  # Nmap grepable output
            parts = value.split()
            if len(parts) < 2:
                raise ValueError('missing address in Nmap Host record')
            self._ip_literal(parts[1])
            for column in value.split('\t'):
                if column.startswith('Ports: '):
                    for record in column[7:].split(','):
                        self._number(record.strip().partition('/')[0], 0, 65535)
        elif '://' in value or value.startswith('['):
            self._endpoint(value)
        else:
            if value.count(':') > 1:
                try:
                    self._ip_literal(value)
                    return
                except ValueError:
                    pass  # Nikto also permits host:port:port.
            parts = re.split('[:,]', value, maxsplit=1)
            self._host(parts[0])
            if len(parts) > 1:
                self._nikto_ports(parts[1].replace(':', ','))

    def _verify_list_file(self, key, check_entry=None):
        """Validate the submitted file and identify the first invalid record.

        Read a regular file line by line, reject binary control characters, and skip
        blank lines and comments. When check_entry is supplied, decode each remaining
        record as UTF-8 before passing it to the callback. Without a callback, check the
        raw bytes for text entries. An empty or unreadable file raises ArgumentIssue for
        key. Record errors also include the one-based line number.
        """
        path = Path(self.argstoverify[key])
        label = next(field['label'] for field in TOOL_MODELS[self.verificationparam] if field['key'] == key)
        count = 0
        try:
            if not path.is_file():
                raise OSError('select a readable regular file')
            with path.open('rb') as stream:
                for line_number, raw in enumerate(stream, 1):
                    if re.search(rb'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', raw):
                        raise ArgumentIssue(key, f'{label}, line {line_number}: expected a text entry')
                    entry = raw.rstrip(b'\r\n')
                    if not entry.strip() or entry.lstrip().startswith(b'#'):
                        continue
                    if check_entry:
                        try:
                            check_entry(entry.decode('utf-8'))
                        except ValueError as error:
                            raise ArgumentIssue(key, f'{label}, line {line_number}: {error}') from error
                    count += 1
        except OSError as error:
            raise ArgumentIssue(key, f'{label}: {error}') from error
        if not count:
            raise ArgumentIssue(key, f'{label}: the file needs at least one entry')
        self._trace(f'{label}: verified {count} list entries')

    def _verify_tool_inputs(self):
        """Apply checks specific to the selected tool's input format.

        Inspect MassDNS lists, optional DIRB/dnsmap wordlists and Nikto host files, or
        enforce MSFPC output combinations. Failures retain the field key for interactive
        correction.
        """
        tool = self.verificationparam
        args = self.argstoverify
        if tool == 'massdns':
            self._verify_list_file(0, self._dns_query_name)
            self._verify_list_file(1, self._massdns_resolver)
        elif tool in ('dirb', 'dnsmap') and args[1]:
            self._verify_list_file(1, self._dns_query_name if tool == 'dnsmap' else None)
        elif tool == 'nikto' and Path(args[0]).is_file():
            self._verify_list_file(0, self._nikto_list_entry)
        elif tool == 'msfpc':
            self._verify_msfpc_setup()
            self._trace('MSFPC setup verified')

    def _verify_network_fields(self):
        """Dispatch address and port checks by tool and field key.

        Require text without control characters, validate nonempty values, and convert
        missing or invalid fields to labeled `ArgumentIssue` exceptions.
        """
        tool = self.verificationparam
        values = self.argstoverify
        checks = {
            'nmap': {0: self._nmap_target, 1: self._nmap_ports, 9: self._ip_literal, 10: self._single_port, 11: self._proxies},
            'nikto': {0: self._nikto_target, 1: self._nikto_ports, 15: self._endpoint, 16: self._endpoint},
            'msfpc': {0: self._msfpc_address, 1: self._single_port},
            'dnsrecon': {0: self._host, 2: self._nameservers},
            'assetfinder': {0: self._host}, 'dnsmap': {0: self._host}, 'dmitry': {0: self._host},
            'wpscan': {0: self._endpoint}, 'dirb': {0: self._endpoint}, 'spiderfoot-cli': {0: self._endpoint},
        }.get(tool, {})
        for field in TOOL_MODELS[tool]:
            key = field['key']
            if key not in checks:
                continue
            try:
                value = values[key]
                if not isinstance(value, str) or any(ord(char) < 32 for char in value):
                    raise ValueError('expected text without control characters')
                if value:
                    checks[key](value)
                    self._trace(f"{field['label']}: address or port verified")
            except (KeyError, IndexError):
                raise ArgumentIssue(key, f"{field['label']}: missing value") from None
            except ValueError as error:
                raise ArgumentIssue(key, f"{field['label']}: {error}") from error

    STANDARD_CATEGORIES = set(
        'all auth broadcast brute default discovery dos exploit external fuzzer intrusive malware safe version vuln'.split()
    )

    @staticmethod
    def _script_directories():
        """Locate candidate Nmap scripts directories in search order.

        Use `NMAPDIR`, per-user data, executable-relative and system paths as
        applicable, followed by the working directory. Return deduplicated candidate
        paths.
        """
        roots = []
        if os.environ.get('NMAPDIR'):
            roots.append(Path(os.environ['NMAPDIR']))
        if os.name != 'nt':
            roots.append(Path.home() / '.nmap')
        elif os.environ.get('APPDATA'):
            roots.append(Path(os.environ['APPDATA']) / 'nmap')
        executable = shutil.which('nmap')
        if executable:
            bindir = Path(executable).resolve().parent
            roots.append(bindir)
            if os.name != 'nt':
                roots.append(bindir.parent / 'share' / 'nmap')
        if os.name != 'nt':
            roots.extend((Path('/usr/local/share/nmap'), Path('/usr/share/nmap')))
        roots.append(Path.cwd())
        return list(dict.fromkeys(root / 'scripts' for root in roots))

    @staticmethod
    def _selector_names(expression):
        """Yield operands from an NSE boolean expression.

        Track parentheses and the position of unary and binary operators. Raise
        `ValueError` on a misplaced token, unbalanced group or unfinished expression
        during iteration.
        """
        expecting_name = True
        depth = 0
        for token in re.findall(r'[()]|[^\s()]+', expression):
            word = token.lower()
            if expecting_name and word == 'not':
                continue
            if expecting_name and token == '(':
                depth += 1
            elif not expecting_name and token == ')' and depth:
                depth -= 1
            elif not expecting_name and word in ('and', 'or'):
                expecting_name = True
            elif expecting_name and word not in ('and', 'or', ')'):
                yield token
                expecting_name = False
            else:
                raise ValueError('Nmap --script: misplaced operator, parenthesis, or script name')
        if expecting_name or depth:
            raise ValueError('Nmap --script: incomplete selector or unbalanced parentheses')

    @staticmethod
    def _script_path(rule, directories):
        """Check whether an NSE operand names a local script or directory.

        Probe the supplied search directories. Accept regular files, implicit `.nse`
        suffixes and directory paths with a trailing separator.
        """
        for directory in directories:
            path = directory / rule
            if rule.endswith(('/', os.sep)):
                if path.is_dir():
                    return True
            elif path.is_file() or Path(str(path) + '.nse').is_file():
                return True
        return False

    @classmethod
    def verify_nse_selector(cls, selector):
        """Validate comma-separated NSE selectors against local data.

        Recognize paths, categories, boolean expressions, script names and star
        patterns. Read the first available `scripts/script.db` and raise `ValueError`
        for invalid syntax or unverifiable names.
        """
        if not isinstance(selector, str) or '\0' in selector:
            raise ValueError('Nmap --script: enter a script name or expression')
        directories = cls._script_directories()
        database = next((path / 'script.db' for path in directories if (path / 'script.db').is_file()), None)
        categories = cls.STANDARD_CATEGORIES.copy()
        names = set()
        if database:
            try:
                catalog = database.read_text(encoding='utf-8')
            except (OSError, UnicodeError) as error:
                raise ValueError(f'Nmap --script: cannot read {database}') from error
            names.update(re.findall(r'\bfilename\s*=\s*"([^"]+)\.nse"', catalog))
            for group in re.findall(r'\bcategories\s*=\s*\{([^}]*)\}', catalog):
                categories.update(category.lower() for category in re.findall(r'"([^"]+)"', group))

        for item in selector.split(','):
            rule = item.strip().removeprefix('+').strip()
            if rule and '*' not in rule and cls._script_path(rule, [*directories, Path.cwd()]):
                continue
            for token in cls._selector_names(rule):
                if token.lower() in categories or token.lower() in ('true', 'false'):
                    continue
                name = token.removesuffix('.nse')
                if name in names:
                    continue
                if '*' in name:
                    # NSE treats only '*' as a wildcard.
                    pattern = name.replace('[', '[[]').replace('?', '[?]')
                    if any(fnmatchcase(script, pattern) for script in names):
                        continue
                if not database:
                    raise ValueError(f'Nmap --script: cannot verify {token!r}. Set NMAPDIR to the Nmap data '
                                     'directory containing scripts/script.db.')
                raise ValueError(f'Nmap --script: unknown script, category, or pattern {token!r}. '
                                 f'Check the spelling or the installed catalog at {database}.')

    def _validate_fields(self):
        """Check required entries and normalize model-backed values.

        Run network checks, then normalize sliders and checkbox representations in the
        working copy. Validate choice and input settings and associate failures with
        their field keys.
        """
        tool = self.verificationparam
        args = self.argstoverify
        missing = missing_required_fields(tool, args)
        if missing:
            labels = ', '.join(field['label'].strip().rstrip('*') for field in missing)
            raise ArgumentIssue(missing[0]['key'], 'Please complete: ' + labels)
        self._trace('required fields present')
        self._verify_network_fields()

        for field in TOOL_MODELS[tool]:
            key = field['key']
            if field['kind'] != 'Slider' and 'setting' not in field:
                continue
            try:
                value = args[key]
            except (KeyError, IndexError):
                raise ArgumentIssue(key, f"{field['label']}: missing value") from None
            try:
                if field['kind'] == 'Slider':
                    args[key] = normalize_slider(field, value)
                    if self.debug:
                        lower, upper = field['range']
                        detail = f'{args[key]} within {lower}..{upper}'
                        if type(value) is not int:
                            detail = f'normalized {value} to {detail}'
                        self._trace(f"{field['label']}: {detail}")
                elif field['kind'] == 'Checkbox':
                    args[key] = enabled(value)
                else:
                    validate_field(field, value[0] if field['kind'] == 'Listbox' else value)
                    self._trace(f"{field['label']}: valid")
            except (IndexError, KeyError, TypeError, ValueError) as error:
                raise ArgumentIssue(key, f"{field['label']}: {error}") from error

    def input_verification(self, confirm_create=None, *, console=None):
        """Validate arguments and prepare writable output destinations.

        Apply setting-backed defaults, check required and network fields, normalize
        model values, and run tool-specific checks. With Nmap NSE enabled, a blank
        selector becomes 'not intrusive' in the working copy. Named scripts and patterns
        may require the local script.db.

        After field validation, prepare_tool_output calls confirm_create(Path) for a
        missing output directory. The terminal prompt is the default callback. A refusal
        sets requires_exit=True and leaves issue as None. A caught validation or I/O
        error sets requires_exit=True and stores the exception in issue. On success,
        requires_exit is False and argstoverify contains the prepared values.

        Return this verifier on each of these paths. The caller handles overwrite
        confirmation separately.
        """
        tool = self.verificationparam
        args = self.argstoverify
        if console is None:
            console = con_host
        self.issue = None
        try:
            if tool not in TOOL_MODELS:
                raise ValueError(f'Unknown tool: {tool}')
            apply_argument_defaults(tool, args, self.rulelist, self._trace)
            self._validate_fields()
            self._verify_tool_inputs()
            if tool == 'nmap' and enabled(self.rulelist['ScriptEnablers']['nmap_nsescriptscan_enable']):
                if args[2] == '':
                    args[2] = 'not intrusive'
                    console.print(Text('  Using the default NSE script expression: not intrusive.', style='bold yellow'))
                    self._trace('NSE script expression defaulted to "not intrusive"')
                try:
                    self.verify_nse_selector(args[2])
                except ValueError as error:
                    raise ArgumentIssue(2, str(error)) from error
                self._trace('Nmap --script selector names verified')
            self._trace('checking output directory and configured report paths')
            try:
                ready = prepare_tool_output(tool, args, self.rulelist, confirm_create or self._confirm_create)
            except OSError as error:
                raise ArgumentIssue(OUTPUT_KEYS[tool], str(error)) from error
            if not ready:
                self._trace('stopped: output directory creation declined')
                self.requires_exit = True
                return self
        except (OSError, ValueError, TypeError) as error:
            self.issue = error
            console.print(Text(f'  {error}', style='bold red'))
            reason = f'output check failed ({type(error).__name__})' if isinstance(error, OSError) else str(error)
            self._trace(f'failed: {reason}')
            self.requires_exit = True
        else:
            self.requires_exit = False
            self._trace('passed: output is writable and arguments are ready')
            console.print(Text(f'  Output stream @ "{args[OUTPUT_KEYS[tool]]}" is usable.', style='bold green'))
        return self


class ToolModule:
    """Prepare execution state shared by ScanTool and HackTool.

    execute_bearer identifies the selected tool. execute_properties references the
    caller's configuration dictionary. The Qt form supplies its per-run copy.
    execute_arguments holds the prepared integer-keyed dictionary or positional list.
    Submissions from either interface use strings for text, integers for sliders,
    booleans for switches and one-element lists for choices. Runner methods use
    module_exec as the instance parameter.

    With ioverify=True, construction runs ArgVerify and raises VerificationFailed if
    preparation stops. A prepared runner exposes the verifier as verified_input. With
    ioverify=False, construction copies the argument container and fills missing
    setting-backed defaults. Direct callers using this mode must supply valid field
    values and prepare the output path. Both modes rely on the caller for configuration
    validation and overwrite consent.
    """

    def __init__(module_exec, toolname: str, config_rules: dict, exec_args: dict, show_debug: bool = False, ioverify: bool = True, *, confirm_create=None):
        """Prepare one tool submission for command construction.

        Store the selected tool, config and debug settings. With verification on, raise
        `VerificationFailed` on a rejected submission. With it off, copy fields and fill
        legacy defaults.
        """

        module_exec.execute_bearer = toolname
        module_exec.execute_properties = config_rules
        module_exec.execute_debugger = show_debug
        module_exec.execute_argverification = ioverify
        module_exec.console_host = gui_console(show_debug) if confirm_create is not None else con_host

        module_exec.trace_step(f'ToolModule.__init__: ArgVerify {"active" if ioverify else "disabled"}')
        if ioverify:
            verifier = ArgVerify(exec_args, toolname, config_rules, debug=show_debug)
            module_exec.verified_input = verifier.input_verification(confirm_create, console=module_exec.console_host)
            if module_exec.verified_input.requires_exit:
                raise VerificationFailed(module_exec.verified_input.issue)
            module_exec.execute_arguments = module_exec.verified_input.argstoverify
            module_exec.console_host.line()
        else:
            if show_debug:
                print_debug(f'ArgVerify ({toolname}): skipped (ioverify=False)')
            args = exec_args.copy() if isinstance(exec_args, dict) else list(exec_args)
            apply_argument_defaults(toolname, args, config_rules)
            module_exec.execute_arguments = args

    def trace_step(self, step):
        """Mark the beginning of one runner step.

        When debugging, include the concrete runner class and tool name. Emitting at
        entry keeps failures in preliminary commands visible.
        """
        if self.execute_debugger:
            print_debug(f'modules_main {type(self).__name__} ({self.execute_bearer}): {step}')


class ScanTool(ToolModule):
    """Build and run commands for the registered scanners.

    build_command() returns the main command for inspection. cmdgen() also runs
    any Nmap preliminary commands and directs assetfinder stdout to its report.

    This example builds the assetfinder command using the configuration shipped
    with the checkout. An existing temporary directory satisfies output verification.

        from tempfile import TemporaryDirectory
        from libasadt4.gui_models import OUTPUT_KEYS
        from libasadt4.mainprog import TOML_Loader
        from libasadt4.modules_main import ScanTool
        from libasadt4.tool_config import initial_values, validate_tool_config

        config = TOML_Loader("config").loadfile("scantool/assetfinder.toml").dictionary
        validate_tool_config("assetfinder", config)
        values = initial_values("assetfinder", config)
        with TemporaryDirectory() as directory:
            values.update({0: "example.org", OUTPUT_KEYS["assetfinder"]: directory})
            argv = ScanTool("assetfinder", config, values).build_command()
            assert argv == ["assetfinder", "-subs-only", "example.org"]
    """

    submodules = ['nmap', 'nikto', 'dnsrecon', 'wpscan', 'assetfinder', 'dirb',
                  'dnsmap', 'massdns', 'dmitry', 'spiderfoot-cli']

    def cmdgen(module_exec):
        """Run the scanner and exit with its status.

        Build the main command first. For Nmap, run the configured NSE database update,
        then the optional traceroute, then the main scan. A failed preliminary command
        exits immediately with its status. For assetfinder, capture stdout in a
        temporary sibling and replace the report only after a successful exit.
        """

        module_exec.trace_step('cmdgen -> build_command')
        command = module_exec.build_command()
        if module_exec.execute_bearer == 'assetfinder':
            report = report_path('assetfinder', module_exec.execute_arguments, module_exec.execute_properties)
            module_exec.trace_step(f'RunCommand: capture stdout to {report}')
            raise SystemExit(RunCommand(command, stdout_path=report, debug=module_exec.execute_debugger))
        if module_exec.execute_bearer == 'nmap':
            if enabled(module_exec.execute_properties['ScriptEnablers']['nmap_updatensedb']):
                module_exec.trace_step('RunCommand: update NSE database')
                status = RunCommand(['nmap', '--script-updatedb'], debug=module_exec.execute_debugger)
                if status:
                    raise SystemExit(status)
            if module_exec.execute_arguments[4]:
                args = module_exec.execute_arguments
                module_exec.trace_step('RunCommand: traceroute')
                trace_command = ['nmap', '--traceroute']
                if args[5]:
                    trace_command.append('-6')
                status = RunCommand([*trace_command, *module_exec.nmap_limits(), args[0]], debug=module_exec.execute_debugger)
                if status:
                    raise SystemExit(status)
        module_exec.trace_step('RunCommand: main scan')
        raise SystemExit(RunCommand(command, debug=module_exec.execute_debugger))

    def nmap_limits(module_exec):
        """Build Nmap's optional timeout and rate arguments.

        Use field 17 as minutes per host and field 18 as a maximum packet rate. Return a
        list of tokens shared by traceroute and the main scan.
        """
        args = module_exec.execute_arguments
        limits = []
        if args[17]:
            limits += ['--host-timeout', f'{args[17]}m']
        if args[18]:
            limits += ['--max-rate', str(args[18])]
        return limits

    def build_command(module_exec):
        """Return the main scanner command as a list of subprocess arguments.

        Read execute_arguments and execute_properties to translate model selections into
        native flags. Each list item is one argument. Emit a flag and its value as
        separate items to preserve paths containing spaces and to let RunCommand redact
        values that follow a sensitive_flag. Use report_path for native output arguments
        so execution and preview resolve the same destination. Nmap -oA uses one
        basename for three report files.

        Translate display choices here. For example, DNSRecon's Standard mode becomes
        std, and its worker count applies only to DNS_THREADED_MODES. Preserve each
        option's native meaning for zero. Nmap timing zero emits -T0, while a zero rate
        limit omits --max-rate. An unknown or disabled scanner exits with status 1.
        """

        args = module_exec.execute_arguments
        rules = module_exec.execute_properties
        tool = module_exec.execute_bearer
        enablers = rules['ScriptEnablers']
        if tool not in module_exec.submodules or not enabled(enablers[tool + '_enable']):
            print('[red bold]  [!] Tool Is Disabled Or Unknown!')
            raise SystemExit(1)
        command = [tool]
        if tool == 'nmap':
            command += ['-p', args[1]]
            if enabled(enablers['nmap_nsescriptscan_enable']):
                if args[2]:
                    command += ['--script', args[2]]
                if args[3]:
                    command += ['--script-args-file', args[3]]
                if args[2] and enabled(enablers['nmap_nsedebug_enable']):
                    command += ['--script-trace']
            for key, flag in ((5, '-6'), (6, '-O'), (14, '--badsum')):
                if args[key]:
                    command += [flag]
            if args[7] != -1:
                command += ['-sV', '--version-intensity', str(args[7])]
            command += ['-T' + str(args[8])]
            command += module_exec.nmap_limits()
            for key, flag in ((9, '-S'), (10, '--source-port'), (11, '--proxies'), (12, '--spoof-mac'), (13, '-e')):
                if args[key]:
                    command += [flag, args[key]]
            scan_methods = {'TCP Syn Scan': '-sS', 'Connect() Scan': '-sT', 'ACK Scan': '-sA',
                            'Window Scan': '-sW', 'Maimon Scan': '-sM', 'UDP Scan': '-sU',
                            'TCP Null Scan': '-sN', 'FIN Scan': '-sF', 'Xmas Scan': '-sX'}
            if args[16]:
                command += [scan_methods[args[16][0]]]
            command += ['--privileged' if enabled(enablers['nmap_assumesudoperms_enable']) else '--unprivileged']
            command += ['-' + rules['ScriptOutput']['nmap_fullscan_output_format'],
                        report_path(tool, args, rules), args[0]]
        elif tool == 'dnsrecon':
            modes = {'Standard': 'std', 'Service records': 'srv', 'Certificate authority records': 'caa'}
            formats = {'JSON': '-j', 'CSV': '-c', 'XML': '-x'}
            report_format = args[5][0]
            command += ['-d', args[0], '-t', modes[args[1][0]]]
            if args[2]:
                command += ['-n', args[2]]
            if args[3]:
                command += ['--tcp']
            if args[6]:
                command += ['--lifetime', str(args[6])]
            if args[7] and args[1][0] in DNS_THREADED_MODES:
                command += ['--threads', str(args[7])]
            command += [formats[report_format], report_path(tool, args, rules)]
        elif tool == 'nikto':
            command += ['-host', args[0]]
            if args[1]:
                command += ['-port', args[1]]
            for key, flag in ((2, '-ipv4'), (3, '-ipv6'), (4, '-ssl'), (5, '-nossl'),
                              (8, '-followredirects'), (9, '-noslash')):
                if args[key]:
                    command += [flag]
            for key, flag in ((6, '-useragent'), (10, '-Tuning'), (11, '-evasion'), (12, '-Cgidirs'),
                              (13, '-timeout'), (14, '-Pause'), (15, '-useproxy'), (16, '-vhost'),
                              (17, '-id'), (18, '-key')):
                if args[key]:
                    command += [flag, str(args[key])]
            if enablers.get('nikto_cli_profile', 'legacy') == 'legacy':
                if args[7]:
                    command += ['-usecookies']
            elif not args[7]:
                command += ['-nocookies']
            if args[20]:
                command += ['-maxtime', f'{args[20]}s']
            if args[21]:
                command += ['-root', args[21]]
            if enabled(enablers['nikto_nointeractive']):
                command += ['-nointeractive']
            command += ['-Display', rules['ScriptEnablers']['nikto_displaytype'],
                        '-o', report_path(tool, args, rules),
                        '-Format', rules['ScriptOutput']['nikto_default_output_format']]
        elif tool == 'wpscan':
            command += ['--format', 'json', '--url', args[0], '--detection-mode', args[1][0]]
            if args[2]:
                command += ['--enumerate', args[2]]
            if args[3]:
                command += ['--max-threads', str(args[3])]
            command += ['--output', report_path(tool, args, rules)]
        elif tool == 'assetfinder':
            if args[1]:
                command.append('-subs-only')
            command.append(args[0])
        elif tool == 'dirb':
            command.append(args[0])
            if args[1]:
                command.append(args[1])
            if args[2]:
                command += ['-X', args[2]]
            if args[3]:
                command.append('-r')
            if args[4]:
                command += ['-z', str(args[4])]
            command += ['-o', report_path(tool, args, rules)]
        elif tool == 'dnsmap':
            command.append(args[0])
            if args[1]:
                command += ['-w', args[1]]
            if args[2]:
                command += ['-d', str(args[2])]
            command += ['-r', report_path(tool, args, rules)]
        elif tool == 'massdns':
            command += ['-o', 'S', '-r', args[1], '-t', args[2][0]]
            if args[3]:
                command += ['-s', str(args[3])]
            command += ['-w', report_path(tool, args, rules), args[0]]
        elif tool == 'dmitry':
            lookup_flags = {'Domain WHOIS': '-w', 'IP WHOIS': '-i'}
            command.append(lookup_flags[args[1][0]])
            for key, flag in ((2, '-s'), (3, '-e'), (4, '-p')):
                if args[key]:
                    command.append(flag)
            command += ['-o', report_path(tool, args, rules), args[0]]
        elif tool == 'spiderfoot-cli':
            command += ['-s', args[0]]
            for key, flag in ((1, '-e'), (2, '-u'), (3, '-P')):
                if args[key]:
                    command += [flag, args[key]]
            if args[4]:
                command.append('-n')
            command += ['-o', report_path(tool, args, rules)]
        return command


class HackTool(ToolModule):
    """Build MSFPC arguments for single, loop or batch output.

    Field 0 holds the address and field 1 the optional port in all modes. In
    single-output mode, both mode radios are clear. Fields 12 through 24 select a format
    by position in MSFPC_FORMATS. Fields 10–11 select the console, 2–3 the direction,
    4–5 the stage and 6–9 the transport. Loop (25) uses the address and optional port.
    Batch (26) also uses the console selection. The verbose setting applies to all three
    modes.

    ToolDialog retains inactive selections when switching modes. Changes to mode support
    must agree across refresh_msfpc_fields, ArgVerify._verify_msfpc_setup and
    build_command so only active selections affect execution. Field 27 supplies the
    child process's working directory. MSFPC determines filenames during execution, so
    overwrite_question requests consent for a nonempty destination directory.
    """

    submodules = ['msfpc']

    def cmdgen(module_exec):
        """Execute MSFPC in the requested output directory.

        Build argv and pass field 27 as the child process's working directory. Exit with
        the returned status, leaving the parent process's working directory intact.
        """

        module_exec.trace_step('cmdgen -> build_command')
        command = module_exec.build_command()
        module_exec.trace_step('RunCommand: generate payloads in the selected directory')
        raise SystemExit(RunCommand(command, cwd=module_exec.execute_arguments[27], debug=module_exec.execute_debugger))

    def build_command(module_exec):
        """Translate single, loop or batch fields to MSFPC argv.

        Select only the positional arguments active for the mode and append `verbose`
        when configured. An unknown or disabled tool exits with status 1.
        """

        args = module_exec.execute_arguments
        rules = module_exec.execute_properties
        if module_exec.execute_bearer != 'msfpc' or not enabled(rules['ScriptEnablers']['msfpc_enable']):
            print('[red bold]  [!] Tool Is Disabled Or Unknown!')
            raise SystemExit(1)
        console = 'msf' if args[11] else 'cmd'
        command = ['msfpc']
        if args[26]:
            command += [console, 'batch', args[0]]
            if args[1]:
                command += [args[1]]
        elif args[25]:
            command += ['loop', args[0]]
            if args[1]:
                command += [args[1]]
        else:
            output_type = next((value for key, value in enumerate(MSFPC_FORMATS, 12) if args[key]), 'windows')
            command += [output_type, args[0]]
            if args[1]:
                command += [args[1]]
            command += [console, 'bind' if args[2] else 'reverse', 'staged' if args[4] else 'stageless',
                        'tcp' if args[6] else 'http' if args[7] else 'https' if args[8] else 'find_port']
        if enabled(rules['ScriptEnablers']['msfpc_verboseout']):
            command += ['verbose']
        return command


toolbox_main = {'scantool': ' '.join(ScanTool.submodules), 'hacktool': ' '.join(HackTool.submodules)}


def run_to_report(command, cwd, report):
    """Capture a subprocess's stdout beside the final report.

    Run `command` in `cwd`, replace the destination after status 0 and remove the
    temporary file on other paths. Return the child status or propagate an OS error.
    """
    output = tempfile.NamedTemporaryFile(dir=os.path.dirname(os.path.abspath(report)), delete=False)
    try:
        with output:
            status = subprocess.call(command, cwd=cwd, stdout=output)
        if status == 0:
            os.replace(output.name, report)
        return status
    finally:
        if os.path.exists(output.name):
            os.unlink(output.name)


def RunCommand(command: list, cwd=None, *, debug=False, stdout_path=None):
    """Run a native argument list and return the subprocess status.

    cwd sets the child's working directory. By default the child inherits the terminal
    streams. Supplying stdout_path stages standard output through run_to_report. Debug
    output records the working directory, argument list, elapsed time and exit status.
    Values following the selected tool's sensitive flags are redacted in the trace. A
    launch or report I/O error returns 127.
    """
    print('[blue bold]  [>] Executing Tool: ' + command[0])
    if debug:
        sensitive_flags = {field['sensitive_flag'] for field in TOOL_MODELS.get(command[0], ())
                           if 'sensitive_flag' in field}
        display_args = ['<redacted>' if index and command[index - 1] in sensitive_flags else arg
                        for index, arg in enumerate(command)]
        print_debug(f'cwd={os.path.abspath(cwd or os.curdir)!r}')
        items = ',\n'.join(f'  {arg!r}' for arg in display_args)
        print_debug(f'argv=[\n{items}\n]')
    con_host.line()
    if debug:
        started = time.monotonic()
    try:
        if stdout_path is None:
            result = subprocess.call(command, cwd=cwd)
        else:
            result = run_to_report(command, cwd, stdout_path)
    except OSError as ErrorID:
        con_host.print(Text(f'  [!] Cannot Start Tool: {ErrorID}', style='bold red'))
        result = 127
    else:
        con_host.line()
        if result == 0:
            con_host.print(Text('  [EXECUTION COMPLETE]', style='bold green'))
        else:
            con_host.print(Text(f'  [EXECUTION FAILED: {result}]', style='bold red'))
    if debug:
        print_debug(f'{command[0]} exit={result} elapsed={time.monotonic() - started:.3f}s')
    con_host.line()
    return result
