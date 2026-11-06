"""Tool forms shared by Qt, argument verification, and command generation.

Each numeric key identifies a submitted value across those three layers.
Sections group widgets for display. A setting links a field to its TOML
default. Sensitive fields carry their native flag so both diagnostic views
can hide the same value.
"""

REPORT_FOLDER_HELP = ('Choose a writable folder for the report, or type a new folder path, such as '
                      '/home/user/reports. ASADT asks before creating it. Set the report filename in Runtime Config.')

TOOL_NAMES = {
    'nmap': 'Nmap', 'nikto': 'Nikto', 'msfpc': 'MSFPC', 'dnsrecon': 'DNSRecon',
    'wpscan': 'WPScan', 'assetfinder': 'assetfinder', 'dirb': 'DIRB', 'dnsmap': 'dnsmap',
    'massdns': 'MassDNS', 'dmitry': 'DMitry', 'spiderfoot-cli': 'SpiderFoot CLI',
}

# Existing TOML files and the command builder use the keys. The GUI shows the labels.
NMAP_SCAN_METHOD_LABELS = {
    'TCP Syn Scan': 'TCP SYN Scan', 'Connect() Scan': 'TCP Connect Scan', 'ACK Scan': 'ACK Scan',
    'Window Scan': 'Window Scan', 'Maimon Scan': 'Maimon Scan', 'UDP Scan': 'UDP Scan',
    'TCP Null Scan': 'TCP Null Scan', 'FIN Scan': 'FIN Scan', 'Xmas Scan': 'Xmas Scan',
}

TOOL_MODELS = {'nmap': [{'key': 0,
           'kind': 'Input',
           'section': 'Targets',
           'label': 'Target Address*',
           'help': 'Enter one computer or network. For one computer, use a name '
                   '(host.example.org), IPv4 (192.0.2.10) or IPv6 (2001:db8::10). Select IPv6 '
                   'scanning for IPv6 targets.\n'
                   'For a network, add a prefix length, such as 192.0.2.0/24 or 2001:db8::/64 '
                   '(IPv4 0–32, IPv6 0–128). In any IPv4 part, use a list (192.0.2.1,4), a range '
                   '(192.0.2.10-20), an open range (192.0.2.250-) or * for every value.'},
          {'key': 1,
           'kind': 'Input',
           'section': 'Targets',
           'label': 'Port or Port Range*',
           'help': 'Try 443 for one port, 80,443 for a list, or 8000-8080 for a range. You can '
                   'mix them. Ports run from 0 to 65535. Use -1024 or 8000- for an open range, '
                   'or - for ports 1 through 65535.\n'
                   'Use service names like https, * for any text or ? for one character. Use '
                   '[1-1024] for known services in that range.\n'
                   'T: selects TCP ports and U: selects UDP ports, as in U:53,123. A prefix '
                   'applies until the next prefix. Choose the matching scan method. Nmap also '
                   'recognizes S: for SCTP and P: for IP protocols (0–255), which need scan '
                   'methods outside this form.'},
          {'key': 2,
           'kind': 'Input',
           'section': 'Scan Tuning',
           'label': 'NSE Scripts',
           'help': 'Choose extra checks to run. Enter an installed script (http-title), category '
                   '(safe), name pattern (http-*), script file (.nse), or a scripts folder '
                   'ending in /. Separate selections with commas.\n'
                   'Combine selections using and, or, not and parentheses, as in (default or '
                   'safe) and not intrusive. Expressions also accept true and false. A leading + '
                   'forces a script to run.\n'
                   'Standard groups include all, auth, broadcast, brute, default, discovery, '
                   'dos, exploit, external, fuzzer, intrusive, malware, safe, version and vuln. '
                   'Your installation may add more.\n'
                   'Enable script scanning in Runtime Config. With Verify Arguments on, blank '
                   'uses not intrusive. With it off, blank leaves out the script selection.'},
          {'key': 3,
           'kind': 'Input',
           'section': 'Scan Tuning',
           'label': 'NSE Script Arguments File',
           'help': 'Enter the path to a text file of settings for the selected scripts, for '
                   'example /home/user/nse-args.txt. Put name=value pairs in the file, separated '
                   'by commas or new lines. Leave blank to use the scripts’ own settings. '
                   'Requires script scanning in Runtime Config.'},
          {'key': 4,
           'kind': 'Checkbox',
           'section': 'Scan Tuning',
           'label': 'Run Traceroute',
           'setting': 'traceroute', 'default_value': False,
           'help': 'Show the network stops on the way to the target. The route appears in the '
                   'terminal before the main scan.'},
          {'key': 5,
           'kind': 'Checkbox',
           'section': 'Scan Tuning',
           'label': 'Use IPv6',
           'setting': 'ipv6', 'default_value': False,
           'help': 'Use IPv6 addresses. For a hostname, look up its IPv6 address. Leave clear '
                   'for IPv4.'},
          {'key': 6,
           'kind': 'Checkbox',
           'section': 'Scan Tuning',
           'label': 'Detect the Operating System',
           'setting': 'os_detection', 'default_value': False,
           'help': 'Ask Nmap to identify the target’s operating system from its network '
                   'responses.'},
          {'key': 7,
           'kind': 'Slider',
           'show_slider': True,
           'section': 'Scan Tuning',
           'label': 'Service Detection Intensity',
           'setting': 'version_intensity', 'legacy_numeric': True,
           'help': 'Choose how thoroughly to identify services and their versions. Use -1 to '
                   'turn this off, 0 for the fewest probes, or 1 through 9 for increasingly '
                   'thorough checks.',
           'range': (-1, 9),
           'default_value': 5},
          {'key': 8,
           'kind': 'Slider',
           'show_slider': True,
           'section': 'Scan Tuning',
           'label': 'Scan Timing Preset',
           'setting': 'timing_preset', 'legacy_numeric': True,
           'help': 'Choose how quickly to scan. 0 and 1 are the slowest, 2 is gentle, 3 is '
                   'normal, 4 is fast, and 5 is fastest. Faster settings can miss replies on '
                   'slow networks.',
           'range': (0, 5),
           'default_value': 3},
          {'key': 9,
           'kind': 'Input',
           'section': 'Network Options',
           'label': 'Spoofed Source IP Address',
           'help': 'Enter the source IP address to put on outgoing packets, such as 192.0.2.10 '
                   'or 2001:db8::10. For a local IPv6 address you can include its interface, as '
                   'in fe80::1%eth0. Leave blank to use the address Nmap selects.'},
          {'key': 10,
           'kind': 'Input',
           'section': 'Network Options',
           'label': 'Source Port',
           'help': 'Enter one port from 1 to 65535, such as 53, to send supported probes from '
                   'that port. Leave blank to let Nmap choose.'},
          {'key': 11,
           'kind': 'Input',
           'section': 'Network Options',
           'label': 'Proxy URL',
            'sensitive_flag': '--proxies',
           'help': 'Enter an HTTP or SOCKS4 proxy, such as http://proxy.example.org:8080 or '
                   'socks4://192.0.2.5:1080. For a chain, separate addresses with commas. Use '
                   'proxies that allow connections without a login. This applies to supported '
                   'script and service-version connections. Leave blank to connect directly.'},
          {'key': 12,
           'kind': 'Input',
           'section': 'Network Options',
           'label': 'Spoofed MAC Address',
           'help': 'Choose the hardware address sent with raw network packets. Enter 0 for a '
                   'random address, a vendor name like Cisco, or up to six pairs of hex digits '
                   'with optional colons (00:11:22:33:44:55). A shorter prefix like 00:11:22 '
                   'fills the rest randomly. Leave blank to use the usual address.'},
          {'key': 13,
           'kind': 'Input',
           'section': 'Network Options',
           'label': 'Network Interface',
           'help': 'Enter the name of the local network connection to scan from, such as eth0 '
                   'for a wired connection or wlan0 for Wi-Fi. Leave blank to let Nmap choose.'},
          {'key': 14,
           'kind': 'Checkbox',
           'section': 'Network Options',
           'label': 'Send Packets with Invalid Checksums',
           'help': 'Send test packets with deliberately incorrect checksums. Most devices '
                   'discard these. Leave clear for ordinary scans.'},
          {'key': 15,
           'kind': 'Input',
           'section': 'Output',
           'label': 'Output Directory',
           'help': REPORT_FOLDER_HELP,
           'directory': True},
          {'key': 16,
           'kind': 'Listbox',
           'section': 'Scan Tuning',
           'label': 'Scan Method',
           'setting': 'scan_method',
           'help': 'Choose one way to test ports. TCP SYN Scan checks whether a connection can '
                   'start. TCP Connect Scan opens a normal TCP connection. UDP Scan tests services '
                   'that use UDP, such as DNS.\n'
                   'ACK Scan tests firewall filtering. Window Scan and Maimon Scan use '
                   'differences in how some systems reply. TCP Null Scan, FIN Scan and Xmas Scan '
                   'send different combinations of TCP flags to look for closed ports.',
           'choices': list(NMAP_SCAN_METHOD_LABELS), 'choice_labels': NMAP_SCAN_METHOD_LABELS},
          {'key': 17, 'kind': 'Slider', 'section': 'Scan Tuning', 'label': 'Host Timeout (Minutes)',
           'range': (0, 10080), 'default_value': 0, 'setting': 'host_timeout_minutes',
           'help': 'Set how many minutes Nmap may spend on each host. Select Tool Default (0) to '
                   'let Nmap manage the time.'},
          {'key': 18, 'kind': 'Slider', 'section': 'Scan Tuning', 'label': 'Maximum Packets per Second',
           'range': (0, 1000000), 'default_value': 0, 'setting': 'max_rate',
           'help': 'Limit how many discovery and port-scan packets Nmap sends per second across '
                   'all hosts. Select Tool Default (0) to let Nmap set the pace.'}],
 'dnsrecon': [{'key': 0, 'kind': 'Input', 'section': 'Target', 'label': 'Domain',
               'help': 'Enter the domain to look up, such as example.org.'},
              {'key': 1, 'kind': 'Listbox', 'section': 'Target', 'label': 'Scan Mode',
               'setting': 'scan_mode',
               'choices': ['Standard', 'Service records', 'Certificate authority records'],
               'choice_labels': {'Service records': 'Service Records',
                                 'Certificate authority records': 'Certificate Authority Records'},
               'help': 'Choose Standard for common domain records, Service Records for the hosts and '
                       'ports of named services, or Certificate Authority Records to see which '
                       'authorities may issue certificates for the domain.'},
              {'key': 2, 'kind': 'Input', 'section': 'Target', 'label': 'DNS Server',
               'setting': 'dns_server', 'help': 'Enter one DNS server name or IPv4 or IPv6 address, such as '
                        'ns.example.org or 2001:db8::53. Separate multiple servers with commas, '
                        'as in 192.0.2.53,192.0.2.54. Leave blank to let DNSRecon choose.'},
              {'key': 3, 'kind': 'Checkbox', 'section': 'Target', 'label': 'Use TCP',
               'setting': 'use_tcp', 'default_value': False,
               'help': 'Send DNS requests over a TCP connection. Leave clear to use DNSRecon’s '
                       'usual transport.'},
              {'key': 4, 'kind': 'Input', 'section': 'Output', 'label': 'Output Directory',
               'help': REPORT_FOLDER_HELP, 'directory': True},
              {'key': 5, 'kind': 'Listbox', 'section': 'Output', 'label': 'Report Format',
               'setting': 'report_format', 'choices': ['JSON', 'CSV', 'XML'],
               'help': 'Choose JSON for structured data, CSV for a spreadsheet, or XML for '
                       'software that reads XML. The report gets the matching file extension.'},
              {'key': 6, 'kind': 'Slider', 'section': 'Target', 'label': 'DNS Response Wait (Seconds)',
               'range': (0, 3600), 'default_value': 0, 'setting': 'lifetime_seconds',
               'help': 'Set how many seconds to wait for a DNS answer. Select Tool Default (0) for '
                       'DNSRecon’s usual wait.'},
              {'key': 7, 'kind': 'Slider', 'section': 'Target', 'label': 'Lookup Threads',
               'range': (0, 256), 'default_value': 0, 'setting': 'threads',
               'help': 'Set how many workers can look up records at once. Select Tool Default (0) '
                       'to let DNSRecon choose. Available for Standard and Service Records.'}],
 'nikto': [{'key': 0,
            'kind': 'Input',
            'section': 'Targets',
            'label': 'Target Address*',
            'help': 'Enter a website such as https://example.org:8443/app, a hostname, or an '
                    'IPv4 or IPv6 address. Add a port after a colon if needed. Use brackets for '
                    'IPv6 with a port, as in [2001:db8::1]:8080.\n'
                    'For multiple targets, enter the path to a text file with one target per '
                    'line. It can contain URLs, addresses, host and port lists '
                    '(host.example.org:80:443), or Nmap grepable Host: records. Use - to read '
                    'targets from the terminal.'},
           {'key': 1,
            'kind': 'Input',
            'section': 'Targets',
            'label': 'Target Port',
            'help': 'Enter 8080 for one port, 80,443 for a list, or 8000-8010 for a range. You '
                    'can mix lists and ranges. Use numbers from 1 to 65535. Leave blank to use '
                    'the port from the target or Nikto’s default.'},
           {'key': 2,
            'kind': 'Radio',
            'section': 'Targets',
            'label': 'Use IPv4',
            'help': 'Connect using IPv4, such as 192.0.2.10.',
            'group_id': 'ip_type',
            'default': True},
           {'key': 3,
            'kind': 'Radio',
            'section': 'Targets',
            'label': 'Use IPv6',
            'help': 'Connect using IPv6, such as 2001:db8::10.',
            'group_id': 'ip_type',
            'default': False},
           {'key': 4,
            'kind': 'Radio',
            'section': 'Targets',
            'label': 'Force SSL',
            'help': 'Use an encrypted HTTPS connection for the target, including on unusual '
                    'ports.',
            'group_id': 'ssl_type',
            'default': False},
           {'key': 5,
            'kind': 'Radio',
            'section': 'Targets',
            'label': 'Disable SSL',
            'help': 'Use plain HTTP for the target. For a site that uses HTTPS, choose Force SSL '
                    'or Automatic SSL Detection.',
            'group_id': 'ssl_type',
            'default': True},
           {'key': 6,
            'kind': 'Input',
            'section': 'Scan Options',
            'label': 'User Agent',
            'help': 'Enter the text the scanner should send as its browser name, for example '
                    'LabScanner/1.0. Leave blank to use Nikto’s usual browser name.'},
           {'key': 7,
            'kind': 'Checkbox',
            'section': 'Scan Options',
            'label': 'Use Cookies',
            'help': 'Keep cookies the website sends and include them in later requests. Clear to '
                    'scan without reusing cookies.'},
           {'key': 8,
            'kind': 'Checkbox',
            'section': 'Scan Options',
            'label': 'Follow Redirects',
            'setting': 'follow_redirects', 'default_value': False,
            'help': 'When a website redirects a request, follow it to the new address.'},
           {'key': 9,
            'kind': 'Checkbox',
            'section': 'Scan Options',
            'label': 'Remove Trailing Slashes',
            'help': 'Remove the final slash from requested paths, so /admin/ is requested as '
                    '/admin.'},
           {'key': 10,
            'kind': 'Input',
            'section': 'Scan Tuning',
            'label': 'Scan Tuning Codes',
            'help': 'Choose which checks to run. Join codes without spaces, as in 123b. Leave '
                    'blank for Nikto’s usual checks. Start with x to exclude categories, as in '
                    'x6.\n'
                    '0 file uploads, 1 interesting files, 2 configuration mistakes or default '
                    'files, 3 exposed information, 4 injected scripts or HTML, 5 reading files '
                    'inside the website, 6 denial of service, 7 reading files elsewhere on the '
                    'server, 8 running commands, 9 database (SQL) injection.\n'
                    'a bypassing login, b identifying software, c including remote code, d web '
                    'services, e administration pages.'},
           {'key': 11,
            'kind': 'Input',
            'section': 'Scan Tuning',
            'label': 'Evasion Codes',
            'help': 'Change how Nikto writes its web requests. Join codes without spaces, as in '
                    '27. Leave blank for ordinary requests.\n'
                    '1 randomly encode the address, 2 insert /./ into the path, 3 end the '
                    'address early, 4 add a long random prefix, 5 add a fake parameter, 6 '
                    'separate request parts with a tab, 7 change letter case, 8 use backslashes.\n'
                    'A uses a carriage return as a separator, B uses a vertical tab. Versions '
                    'that offer R can send a random browser name with each request.'},
           {'key': 12,
            'kind': 'Input',
            'section': 'Scan Tuning',
            'label': 'CGI Directories',
            'help': 'Choose which CGI folders (folders for server-side programs) to check. Enter '
                    'all, none, or paths separated by spaces, such as /cgi-bin/ /scripts/. Leave '
                    'blank for Nikto’s configured folders.'},
           {'key': 13,
            'kind': 'Slider',
            'section': 'Scan Tuning',
            'label': 'Request Timeout (Seconds)',
            'setting': 'request_timeout_seconds', 'legacy_numeric': True,
            'show_slider': True,
            'help': 'Set how many seconds to wait for a single request before giving up.',
            'range': (1, 100),
            'default_value': 10},
           {'key': 14,
            'kind': 'Slider',
            'section': 'Scan Tuning',
            'label': 'Pause between Tests (Seconds)',
            'setting': 'pause_seconds', 'legacy_numeric': True,
            'show_slider': True,
            'help': 'Set how many seconds to pause between tests. Use 0 to send the next request '
                    'without an added pause.',
            'range': (0, 100),
            'default_value': 0},
           {'key': 15,
            'kind': 'Input',
            'section': 'Connection Settings',
            'label': 'Proxy URL',
            'sensitive_flag': '-useproxy',
            'help': 'Enter the HTTP proxy address, for example http://proxy.example.org:8080. '
                    'Leave blank to run without a proxy override.'},
           {'key': 16,
            'kind': 'Input',
            'section': 'Connection Settings',
            'label': 'Virtual Host',
            'help': 'If several websites share the target address, enter the site name to send '
                    'in the Host header, such as shop.example.org or shop.example.org:8080. '
                    'Leave blank to use the target’s host.'},
           {'key': 17,
            'kind': 'Input',
            'section': 'Connection Settings',
            'label': 'Host Credentials',
            'sensitive_flag': '-id',
            'help': 'Enter the website login as username:password. If it requires a login realm, '
                    'use username:password:realm. Leave blank to scan without supplying a login.'},
           {'key': 18,
            'kind': 'Input',
            'section': 'Connection Settings',
            'label': 'Client Private Key File',
            'sensitive_flag': '-key',
            'help': 'Enter the path to the client’s private key file, for example '
                    '/home/user/client.key. Leave blank if the site does not require a client '
                    'key.'},
           {'key': 19,
            'kind': 'Input',
            'section': 'Output',
            'label': 'Output Directory',
            'help': REPORT_FOLDER_HELP,
            'directory': True},
           {'key': 20, 'kind': 'Slider', 'section': 'Scan Tuning', 'label': 'Maximum Time per Host (Seconds)',
            'range': (0, 604800), 'default_value': 0, 'setting': 'max_time_seconds',
            'help': 'Limit the total number of seconds spent on each host. Select Tool Default (0) '
                    'to leave timing to Nikto.'},
           {'key': 21, 'kind': 'Input', 'section': 'Targets', 'label': 'Application Root Path',
            'setting': 'root_path', 'help': 'Enter the part of the website where testing should start. Begin with /, '
                        'as in /portal. Leave blank to use the target as entered.'}],
 'msfpc': [{'key': 0,
            'kind': 'Input',
            'section': 'Connection',
            'label': 'Connection Address*',
            'help': 'Enter the connection address, such as 192.0.2.10, a hostname like '
                    'lab.example.org, or a local network interface name like eth0. Use the '
                    'address the other end can reach.'},
           {'key': 1,
            'kind': 'Input',
            'section': 'Connection',
            'label': 'Connection Port',
            'help': 'Enter one connection port from 1 to 65535, such as 4444. Leave blank for '
                    'the MSFPC default (443).'},
           {'key': 2,
            'kind': 'Radio',
            'section': 'Connection Direction',
            'label': 'Bind',
            'help': 'The target listens for a connection and you connect to it. Choose TCP for '
                    'this direction.',
            'group_id': 'serve_type',
            'default': False},
           {'key': 3,
            'kind': 'Radio',
            'section': 'Connection Direction',
            'label': 'Reverse',
            'help': 'The target connects back to the supplied address and port. Use an address '
                    'the target can reach.',
            'group_id': 'serve_type',
            'default': True},
           {'key': 4,
            'kind': 'Radio',
            'section': 'Staging',
            'label': 'Staged',
            'help': 'Start with a small program that downloads the remaining code when it '
                    'connects.',
            'group_id': 'stage_type',
            'default': True},
           {'key': 5,
            'kind': 'Radio',
            'section': 'Staging',
            'label': 'Stageless',
            'help': 'Include the full program in the generated file so it can start in one step.',
            'group_id': 'stage_type',
            'default': False},
           {'key': 6,
            'kind': 'Radio',
            'section': 'Transport',
            'label': 'TCP',
            'help': 'Use a direct TCP connection. This works with either Bind or Reverse.',
            'group_id': 'net_type',
            'default': True},
           {'key': 7,
            'kind': 'Radio',
            'section': 'Transport',
            'label': 'HTTP',
            'help': 'Use HTTP requests for the connection. Choose Reverse for this transport.',
            'group_id': 'net_type',
            'default': False},
           {'key': 8,
            'kind': 'Radio',
            'section': 'Transport',
            'label': 'HTTPS',
            'help': 'Use encrypted HTTPS requests for the connection. Choose Reverse for this '
                    'transport.',
            'group_id': 'net_type',
            'default': False},
           {'key': 9,
            'kind': 'Radio',
            'section': 'Transport',
            'label': 'Find an Open Port',
            'help': 'Try different ports to find one that allows an outgoing connection. Choose '
                    'Reverse. The Apache Tomcat format requires a specific transport.',
            'group_id': 'net_type',
            'default': False},
           {'key': 10,
            'kind': 'Radio',
            'section': 'Console',
            'label': 'Command Shell',
            'help': 'Open a normal command shell on the target. This selects the system command '
                    'prompt.',
            'group_id': 'con_type',
            'default': False},
           {'key': 11,
            'kind': 'Radio',
            'section': 'Console',
            'label': 'Meterpreter',
            'help': 'Use Meterpreter, the interactive session provided by Metasploit.',
            'group_id': 'con_type',
            'default': True},
           {'key': 12,
            'kind': 'Radio',
            'section': 'Payload Format',
            'label': 'APK',
            'help': 'Create an Android application package (.apk).',
            'group_id': 'syntax_type',
            'default': False},
           {'key': 13,
            'kind': 'Radio',
            'section': 'Payload Format',
            'label': 'ASP',
            'help': 'Create a classic ASP web page (.asp) for a Windows web server. Choose '
                    'Staged with Meterpreter.',
            'group_id': 'syntax_type',
            'default': False},
           {'key': 14,
            'kind': 'Radio',
            'section': 'Payload Format',
            'label': 'ASPX',
            'help': 'Create an ASP.NET web page (.aspx) for a Windows web server.',
            'group_id': 'syntax_type',
            'default': False},
           {'key': 15,
            'kind': 'Radio',
            'section': 'Payload Format',
            'label': 'Bash',
            'help': 'Create a Bash shell script (.sh). Choose Command Shell, Staged, Reverse and '
                    'TCP.',
            'group_id': 'syntax_type',
            'default': False},
           {'key': 16,
            'kind': 'Radio',
            'section': 'Payload Format',
            'label': 'Java',
            'help': 'Create a JavaServer Pages file (.jsp) for a Java web server. Choose Staged with '
                    'Meterpreter.',
            'group_id': 'syntax_type',
            'default': False},
           {'key': 17,
            'kind': 'Radio',
            'section': 'Payload Format',
            'label': 'Linux',
            'help': 'Create a Linux executable (.elf). Choose Staged with Meterpreter.',
            'group_id': 'syntax_type',
            'default': False},
           {'key': 18,
            'kind': 'Radio',
            'section': 'Payload Format',
            'label': 'macOS',
            'help': 'Create a macOS executable (Mach-O). Choose Stageless and Command Shell.',
            'group_id': 'syntax_type',
            'default': False},
           {'key': 19,
            'kind': 'Radio',
            'section': 'Payload Format',
            'label': 'Perl',
            'help': 'Create a Perl script (.pl). Choose Command Shell, Staged and TCP.',
            'group_id': 'syntax_type',
            'default': False},
           {'key': 20,
            'kind': 'Radio',
            'section': 'Payload Format',
            'label': 'PHP',
            'help': 'Create a PHP script (.php) for a web server that runs PHP. Choose '
                    'Meterpreter.',
            'group_id': 'syntax_type',
            'default': False},
           {'key': 21,
            'kind': 'Radio',
            'section': 'Payload Format',
            'label': 'PowerShell',
            'help': 'Create a Windows PowerShell script (.ps1).',
            'group_id': 'syntax_type',
            'default': False},
           {'key': 22,
            'kind': 'Radio',
            'section': 'Payload Format',
            'label': 'Python',
            'help': 'Create a Python script (.py). With Command Shell choose Stageless and '
                    'Reverse. With Meterpreter choose Staged.',
            'group_id': 'syntax_type',
            'default': False},
           {'key': 23,
            'kind': 'Radio',
            'section': 'Payload Format',
            'label': 'Apache Tomcat',
            'help': 'Create a Java web application archive (.war) for Tomcat. Choose TCP, HTTP '
                    'or HTTPS. With Meterpreter choose Staged. With Stageless choose Reverse.',
            'group_id': 'syntax_type',
            'default': False},
           {'key': 24,
            'kind': 'Radio',
            'section': 'Payload Format',
            'label': 'Win32',
            'help': 'Create a Windows executable (.exe).',
            'group_id': 'syntax_type',
            'default': True},
           {'key': 25,
            'kind': 'Radio',
            'section': 'Output Mode',
            'label': 'Loop (One of Each Format)',
            'help': 'Generate one of each format using the address and optional port. MSFPC '
                    'picks the other settings for each format.',
            'group_id': 'ss_type',
            'default': False},
           {'key': 26,
            'kind': 'Radio',
            'section': 'Output Mode',
            'label': 'Batch (Multiple Combinations)',
            'help': 'Generate multiple combinations using the selected console, address and '
                    'optional port. MSFPC chooses the formats, directions, stages and '
                    'transports.',
            'group_id': 'ss_type',
            'default': False},
           {'key': 27,
            'kind': 'Input',
            'section': 'Output',
            'label': 'Output Directory',
            'help': 'Choose a writable folder for the generated files, or type a new folder '
                    'path, such as /home/user/payloads. ASADT asks before creating it. MSFPC '
                    'chooses the filenames.',
            'directory': True}]}


# Shared form requirements; keep numeric keys compatible with existing callers.
OUTPUT_KEYS = {'nmap': 15, 'nikto': 19, 'msfpc': 27, 'dnsrecon': 4}
DNS_THREADED_MODES = ('Standard', 'Service records')
REQUIRED_KEYS = {'nmap': (0, 1, 15), 'nikto': (0, 19), 'msfpc': (0, 27), 'dnsrecon': (0, 4)}
RADIO_DEFAULTS = {
    'ss_type': 'Single Output (Default)',
    'ssl_type': 'Automatic SSL Detection',
}

def field(setting, label, help_text, *, kind='Input', section='Options', **options):
    """Build a field descriptor for the reconnaissance tool registry.

    Combine the TOML setting, UI label, help text, kind and section with tool-specific
    options. Text inputs receive the native-argument validation flag.
    """
    return dict(setting=setting, label=label, help=help_text, kind=kind,
                section=section, native_input=(kind == 'Input'), **options)


def target(setting, label, example, **options):
    """Define a required field in the Target section.

    Use `example` as field help and forward options such as `input_file` to the shared
    descriptor factory.
    """
    return field(setting, label, example, section='Target', required=True, **options)


def switch(setting, label, help_text, default=False):
    """Describe a boolean tool option for a checkbox.

    Store the setting name, label, help and initial checked state. The form and terminal
    defaults consume the same record.
    """
    return field(setting, label, help_text, kind='Checkbox', default_value=default)


def limit(setting, label, help_text, maximum):
    """Describe a bounded integer tool option.

    Set an inclusive range from zero through `maximum`. The zero default lets the
    command builder omit the corresponding native limit.
    """
    return field(setting, label, help_text, kind='Slider', range=(0, maximum), default_value=0)


RECON_FIELDS = {
    'wpscan': [
        target('url', 'WordPress URL', 'Enter the web address of the WordPress installation, including http:// '
               'or https://. Include its port or folder if needed, as in https://example.org:8443/blog/.'),
        field('detection_mode', 'Detection Mode', 'Passive looks for clues in normal page responses. Aggressive '
              'sends extra requests to check for components. Mixed uses both methods.',
              kind='Listbox', choices=['mixed', 'passive', 'aggressive'],
              choice_labels={'mixed': 'Mixed', 'passive': 'Passive', 'aggressive': 'Aggressive'}),
        field('enumerate', 'Enumeration Codes', 'Choose what to look for. Separate codes with commas, as in vp,vt,u1-5. '
              'Leave blank for the usual WPScan run.\n'
              'Plugins (choose at most one): vp vulnerable, ap all, p popular.\n'
              'Themes (choose at most one): vt vulnerable, at all, t popular.\n'
              'tt finds TimThumb image scripts, cb configuration backups, dbe database exports, '
              'and bf backup folders on versions that support it.\n'
              'u checks user IDs 1–10 and m checks media IDs 1–100. To choose a range, use u1-5 or m1-15.'),
        limit('max_threads', 'Maximum Threads', 'Limit the number of workers checking the site at once. '
              'Select Tool Default (0) to let WPScan choose.', 256),
    ],
    'assetfinder': [
        target('domain', 'Domain', 'Enter one domain name, such as example.org. Omit https:// and any page path.'),
        switch('subs_only', 'Show Subdomains Only', 'Show only names under the domain you entered, such as '
               'mail.example.org. Clear to include other related domains.', True),
    ],
    'dirb': [
        target('url', 'Base URL', 'Enter the web address to start searching, such as https://example.org/ '
               'or http://example.org:8080/shop/.'),
        field('wordlist', 'Wordlist File', 'Choose a text file with one name to try per line, such as admin '
              'or login. Leave blank to use the supplied word list.', input_file=True),
        field('extensions', 'Extensions', 'Enter file endings with their dots. Separate them with commas, '
              'as in .php,.html, to try those endings on each name. Leave blank to use the list as supplied.'),
        switch('no_recursion', 'Search Only the Starting Directory', 'Search only the starting folder. Clear to also search '
               'inside folders that DIRB discovers.'),
        limit('delay_ms', 'Request Delay (ms)', 'Set the wait between requests in milliseconds '
              '(1000 is one second). Select Tool Default (0) for DIRB’s usual pace.', 300000),
    ],
    'dnsmap': [
        target('domain', 'Domain', 'Enter the domain to search under, such as example.org. Omit https:// and any page path.'),
        field('wordlist', 'Wordlist File', 'Choose a text file with one name per line, such as mail or www. '
              'dnsmap tries each name under your domain. Leave blank for its built-in list.', input_file=True),
        limit('delay_ms', 'Maximum Random Delay (ms)', 'Set the longest random wait between lookups in milliseconds '
              '(1000 is one second). Select Tool Default (0) for dnsmap’s usual timing.', 300000),
    ],
    'massdns': [
        target('domain_file', 'Domain List File', 'Choose a UTF-8 text file with at least one DNS name and one '
               'name per line, such as www.example.org. Names may end with a dot, begin with *. for a wildcard, '
               'or be a single dot for the DNS root.', input_file=True),
        field('resolvers', 'Resolver List File', 'Choose a UTF-8 text file with at least one DNS server IP address, '
              'one per line. Use IPv4 (192.0.2.53) or IPv6 (2001:db8::53) without an interface suffix. '
              'For a custom port from 1 to 65534, use 192.0.2.53:5353 or [2001:db8::53]:5353.',
              input_file=True, required=True),
        field('record_type', 'DNS Record Type', 'Choose the information to look up for each name. A gives an IPv4 '
              'address, AAAA an IPv6 address, CNAME an alias destination, MX a mail server, NS a name server, '
              'PTR the name for a reverse lookup, and TXT a text record.',
              kind='Listbox', choices=['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'TXT']),
        limit('concurrency', 'Concurrent Lookups', 'Limit how many DNS lookups can run at once. '
              'Select Tool Default (0) to let MassDNS choose.', 1000000),
    ],
    'dmitry': [
        target('host', 'Host', 'Enter one hostname such as www.example.org or an IPv4 address such as 192.0.2.10.'),
        field('lookup', 'Primary Lookup', 'Domain WHOIS looks up the registration of the domain name. '
              'IP WHOIS looks up the network registration for the IP address.', kind='Listbox',
              choices=['Domain WHOIS', 'IP WHOIS']),
        switch('subdomains', 'Search for Subdomains', 'Also look for names under the domain, such as mail.example.org.'),
        switch('emails', 'Search for Email Addresses', 'Also look for publicly listed email addresses related to the host.'),
        switch('port_scan', 'Scan TCP Ports', 'Also check which TCP ports accept connections on the host.'),
    ],
    'spiderfoot-cli': [
        target('server_url', 'SpiderFoot Server URL', 'Enter the web address of a running SpiderFoot server, '
               'including its port. For a server on this computer, try http://127.0.0.1:5001.',
               default_value='http://127.0.0.1:5001'),
        field('commands_file', 'Command File', 'Choose a text file containing SpiderFoot client commands to run. '
              'Leave blank to type commands in the terminal.', input_file=True),
        field('username', 'Server Username', 'Enter your SpiderFoot login name, such as analyst. '
              'Leave blank if the server allows access without a login.', sensitive_flag='-u'),
        field('password_file', 'Password File', 'Choose a file containing your SpiderFoot password. '
              'Leave blank to run without supplying a password file.', input_file=True, sensitive_flag='-P'),
        switch('no_history', 'Disable Command History', 'Keep commands out of the local history file. '
               'Clear to allow SpiderFoot to save command history.', True),
    ],
}

for fields in RECON_FIELDS.values():
    fields.append(dict(kind='Input', section='Output', label='Output Directory',
                       help=REPORT_FOLDER_HELP, required=True, directory=True))
    for index, item in enumerate(fields):
        item['key'] = index

TOOL_MODELS.update(RECON_FIELDS)
for tool, fields in RECON_FIELDS.items():
    OUTPUT_KEYS[tool] = next(item['key'] for item in fields if item.get('directory'))
    REQUIRED_KEYS[tool] = tuple(item['key'] for item in fields if item.get('required'))
