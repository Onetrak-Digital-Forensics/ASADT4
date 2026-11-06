import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from unittest.mock import patch

from PySide6.QtCore import QTimer, QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication, QCheckBox, QComboBox, QFormLayout, QLineEdit, QPushButton, QSlider
from shiboken6 import delete
from libasadt4.displayboxhandler import DisplayBoxHandler_Service, ToolDialog
from libasadt4.gui_models import OUTPUT_KEYS
from libasadt4.mainprog import TOML_Loader, CnfEdit, ProgUpdate
from libasadt4.modules_main import ArgVerify, ScanTool, HackTool, RunCommand
from libasadt4.tool_config import validate_tool_config

ROOT = Path(__file__).resolve().parents[1]


class RegressionTests(unittest.TestCase):
    """Exercise the CLI, Qt forms, validation and tool runners together.

    Use a shared offscreen Qt application and per-test temporary directories. Subprocess
    and HTTP doubles cover command construction and failure handling.
    """

    @classmethod
    def setUpClass(cls):
        """Initialize Qt once for the test class.

        Retain a service instance so widgets and dialogs can share the same application
        across cases.
        """
        cls.service = DisplayBoxHandler_Service()

    @classmethod
    def tearDownClass(cls):
        """Flush deferred Qt deletions at class teardown.

        Send pending deferred-delete events after the last test using the shared
        application.
        """
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)

    def setUp(self):
        """Allocate an isolated output directory for each test.

        Register cleanup with unittest so report and configuration fixtures are removed
        after the case.
        """
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def form(self, name, config=None):
        """Construct a test dialog with optional tool configuration.

        Return the dialog and register explicit Qt object deletion with the test's
        cleanup stack.
        """
        dialog = ToolDialog(name, config=config)
        self.addCleanup(delete, dialog)
        return dialog

    def massdns_inputs(self):
        """Create a minimal domain list and resolver list.

        Write one valid record to each temporary file and return their string paths in
        submission order.
        """
        paths = [Path(self.temp.name, filename) for filename in ('domain list.txt', 'resolvers.txt')]
        paths[0].write_text('example.test\n')
        paths[1].write_text('192.0.2.53\n')
        return list(map(str, paths))

    def module(self, name, edits=None, verify=True):
        """Prepare a real runner backed by isolated field values.

        Collect form defaults, supply a local target and output path, overlay edits and
        load the selected tool's TOML. Return a scanner or MSFPC runner using the
        requested verification mode.
        """
        values = self.form(name).collect_values()
        values[0] = '127.0.0.1'
        values[OUTPUT_KEYS[name]] = self.temp.name
        if name == 'nmap':
            values[1] = '80,443'
        if name == 'massdns':
            values.update(enumerate(self.massdns_inputs()))
        values.update(edits or {})
        group = 'hacktool' if name == 'msfpc' else 'scantool'
        rules = TOML_Loader(str(ROOT / 'config')).loadfile(f'{group}/{name}.toml').dictionary
        module_type = HackTool if name == 'msfpc' else ScanTool
        return module_type(name, rules, values, ioverify=verify)

    def test_gui_value_contract_and_defaults(self):
        """Nmap, Nikto and MSFPC expose contiguous field keys and the expected defaults."""
        for name, count in (('nmap', 19), ('nikto', 22), ('msfpc', 28), ('dnsrecon', 8)):
            with self.subTest(tool=name):
                values = self.form(name).collect_values()
                self.assertEqual(set(values), set(range(count)))
        self.assertEqual(self.form('nmap').collect_values()[16], ['TCP Syn Scan'])
        self.assertEqual(self.form('nmap').collect_values()[7], 5)
        self.assertTrue(self.form('nikto').collect_values()[2])
        self.assertTrue(self.form('msfpc').collect_values()[24])

    def test_saved_scan_defaults_reach_form_and_terminal(self):
        """Custom scan defaults drive the same controls and arguments in both entry points."""
        from asadt import terminal_values
        from libasadt4.privileges import privilege_reasons

        cases = (
            ('nmap', {'scan_method': 'Connect() Scan', 'ipv6': True, 'traceroute': True,
                      'os_detection': True, 'timing_preset': 0, 'version_intensity': -1},
             {16: ['Connect() Scan'], 5: True, 4: True, 6: True, 8: 0, 7: -1}),
            ('nikto', {'follow_redirects': True, 'request_timeout_seconds': 1, 'pause_seconds': 2},
             {8: True, 13: 1, 14: 2}),
            ('dnsrecon', {'scan_mode': 'Service records', 'use_tcp': True},
             {1: ['Service records'], 3: True}),
        )
        for tool, defaults, expected in cases:
            with self.subTest(tool=tool):
                config = TOML_Loader(str(ROOT / 'config')).loadfile(f'scantool/{tool}.toml').dictionary
                config['Defaults'].update(defaults)
                validate_tool_config(tool, config)
                gui = self.form(tool, config).collect_values()
                target = '::1' if tool == 'nmap' else 'example.org'
                ports = '80' if tool == 'nmap' else None
                cli = terminal_values(tool, config, target, self.temp.name, ports, None)
                for key, value in expected.items():
                    self.assertEqual(gui[key], value)
                    self.assertEqual(cli[key], value)
                runner = ScanTool(tool, config, cli)
                command = runner.build_command()
                if tool == 'nmap':
                    for flag in ('-sT', '-6', '-O', '-T0'):
                        self.assertIn(flag, command)
                    self.assertNotIn('-sV', command)
                    with patch('libasadt4.modules_main.RunCommand', return_value=0) as run, self.assertRaises(SystemExit):
                        runner.cmdgen()
                    self.assertIn('-6', run.call_args_list[0].args[0])
                    self.assertIn('--traceroute', run.call_args_list[0].args[0])
                    config['ScriptEnablers']['nmap_assumesudoperms_enable'] = False
                    with patch('os.geteuid', return_value=1000, create=True):
                        self.assertEqual(privilege_reasons(tool, config), privilege_reasons(tool, config, cli))
                        config['Defaults'].update(traceroute=False, os_detection=False)
                        self.assertEqual(privilege_reasons(tool, config), [])
                elif tool == 'nikto':
                    self.assertIn('-followredirects', command)
                    self.assertEqual(command[command.index('-timeout') + 1], '1')
                    self.assertEqual(command[command.index('-Pause') + 1], '2')
                else:
                    self.assertEqual(command[command.index('-t') + 1], 'srv')
                    self.assertIn('--tcp', command)

    def test_slider_drag_and_numeric_entry_share_the_submitted_value(self):
        """Moving the slider or editing its spin box updates the same submitted integer."""
        for tool, fields in (('nmap', [(7, -1, 9, 5), (8, 0, 5, 3)]),
                             ('nikto', [(13, 1, 100, 10), (14, 0, 100, 0)])):
            dialog = self.form(tool)
            sliders = {s.accessibleName(): s for s in dialog.findChildren(QSlider)}
            self.assertEqual(len(sliders), len(fields))
            for key, low, high, default in fields:
                with self.subTest(tool=tool, key=key):
                    number = dialog.fields[key]
                    slider = sliders[number.accessibleName()]
                    self.assertEqual((slider.minimum(), slider.maximum(), slider.value()), (low, high, default))
                    slider.setSliderDown(True)
                    slider.setSliderPosition(high)
                    slider.setSliderDown(False)
                    self.assertEqual(dialog.collect_values()[key], high)
                    number.setValue(low)
                    self.assertEqual(slider.value(), low)
                    self.assertEqual(dialog.collect_values()[key], low)

    def test_hover_help_on_all_tool_and_runtime_fields(self):
        """Every input row explains its choices, including labels and compound controls."""
        for tool in ScanTool.submodules + HackTool.submodules:
            group = 'hacktool' if tool == 'msfpc' else 'scantool'
            config = TOML_Loader(str(ROOT / 'config')).loadfile(f'{group}/{tool}.toml').dictionary
            dialog = self.form(tool, config)
            for form in dialog.findChildren(QFormLayout):
                for row in range(form.rowCount()):
                    item = form.itemAt(row, QFormLayout.ItemRole.FieldRole)
                    label = form.itemAt(row, QFormLayout.ItemRole.LabelRole)
                    if label is None:
                        continue  # Standalone controls are checked below.
                    tip = label.widget().toolTip()
                    with self.subTest(tool=tool, field=label.widget().text()):
                        self.assertTrue(tip)
                        if item.layout():  # Slider and spin box share a row.
                            controls = [item.layout().itemAt(i).widget() for i in range(item.layout().count())]
                        elif item.widget().findChildren(QPushButton):  # Path field and Browse button.
                            controls = item.widget().findChildren(QLineEdit) + item.widget().findChildren(QPushButton)
                        else:
                            controls = [item.widget()]
                        for control in controls:
                            self.assertEqual(control.toolTip(), tip)
            controls = [*dialog.fields.values(), *dialog.findChildren(QCheckBox)]
            for radio_group in dialog.groups.values():
                controls.extend(radio_group.buttons())
            for control in controls:
                with self.subTest(tool=tool, field=control.accessibleName() or control.text()):
                    self.assertTrue(control.toolTip())
                    self.assertTrue(control.accessibleDescription())
                    if isinstance(control, QComboBox):
                        for index in range(control.count()):
                            self.assertIn(control.itemText(index).lower(), control.accessibleDescription().lower())

    def test_radio_groups_and_single_output_reset(self):
        """A radio selection clears its peers, and MSFPC can return to single output."""
        dialog = self.form('msfpc')
        dialog.fields[25].setChecked(True)
        self.assertTrue(dialog.collect_values()[25])
        dialog.groups['ss_type'].buttons()[0].setChecked(True)
        self.assertFalse(dialog.collect_values()[25])
        dialog.fields[7].setChecked(True)
        self.assertFalse(dialog.collect_values()[6])

    def test_required_fields_keep_dialog_open(self):
        """A missing required value leaves the dialog open after one warning."""
        dialog = self.form('nmap')
        with patch('libasadt4.displayboxhandler.QMessageBox.warning') as warning:
            dialog.request_execute()
        warning.assert_called_once()
        self.assertEqual(dialog.action, 'quit')

    def test_execute_and_edit_actions(self):
        """Run and Edit TOML produce distinct service actions."""
        dialog = self.form('nmap')
        for key, text in ((0, '127.0.0.1'), (1, '80'), (15, self.temp.name)):
            dialog.fields[key].setText(text)
        dialog.fields[16].setCurrentText('TCP Connect Scan')
        dialog.request_execute()
        self.assertEqual(dialog.action, 'execute')
        dialog.request_edit()
        self.assertEqual(dialog.action, 'edit')

    def test_service_close_and_edit_flags_reset(self):
        """Service flags reflect the most recent dialog when a service is reused."""
        for action in ('request_edit', 'reject'):
            def finish():
                """Trigger edit or cancel once the modal dialog is visible."""
                for window in self.service.application.topLevelWidgets():
                    if isinstance(window, ToolDialog) and window.isVisible():
                        getattr(window, action)()
            QTimer.singleShot(0, finish)
            result = self.service.DISPLAY_UI_MODEL('nikto')
            self.assertEqual(result.ui_request_editcnf, action == 'request_edit')
            self.assertEqual(result.ui_request_exit, action == 'reject')

    def test_every_registered_tool_has_gui_and_config(self):
        """Every registered tool has a configuration, form, required output field and native command."""
        from libasadt4.gui_models import TOOL_MODELS, OUTPUT_KEYS, REQUIRED_KEYS
        self.assertEqual(set(ScanTool.submodules + HackTool.submodules), set(TOOL_MODELS))
        for name in TOOL_MODELS:
            dialog = self.form(name)
            self.assertIn(OUTPUT_KEYS[name], REQUIRED_KEYS[name])
            self.assertEqual(dialog.fields[OUTPUT_KEYS[name]].placeholderText(), 'Required')
            self.assertTrue(self.module(name).build_command())

    def test_nikto_ssl_can_return_to_automatic(self):
        """Automatic SSL clears both Nikto override fields and omits both native switches."""
        dialog = self.form('nikto')
        dialog.fields[4].setChecked(True)
        dialog.groups['ssl_type'].buttons()[0].setChecked(True)
        values = dialog.collect_values()
        self.assertFalse(values[4])
        self.assertFalse(values[5])
        command = self.module('nikto', values, verify=False).build_command()
        self.assertNotIn('-ssl', command)
        self.assertNotIn('-nossl', command)

    def test_recon_toml_options_reach_native_commands(self):
        """Reconnaissance defaults determine form values, preview paths and native commands."""
        domains, resolvers = self.massdns_inputs()
        url = 'https://lab.test/'
        host = 'lab.test'
        report = str(Path(self.temp.name, 'custom report.txt'))
        cases = [
            ('wpscan', dict(url=url, detection_mode='passive', enumerate='vp,vt', max_threads=3),
             ['--format', 'json', '--url', url, '--detection-mode', 'passive', '--enumerate', 'vp,vt',
              '--max-threads', '3', '--output', report]),
            ('assetfinder', dict(domain=host, subs_only='False'), [host]),
            ('dirb', dict(url=url, wordlist=domains, extensions='.php,.html', no_recursion=True, delay_ms=12),
             [url, domains, '-X', '.php,.html', '-r', '-z', '12', '-o', report]),
            ('dnsmap', dict(domain=host, wordlist=domains, delay_ms=71),
             [host, '-w', domains, '-d', '71', '-r', report]),
            ('massdns', dict(domain_file=domains, resolvers=resolvers, record_type='MX', concurrency=15),
             ['-o', 'S', '-r', resolvers, '-t', 'MX', '-s', '15', '-w', report, domains]),
            ('dmitry', dict(host=host, lookup='IP WHOIS', subdomains=True, emails=True, port_scan=True),
             ['-i', '-s', '-e', '-p', '-o', report, host]),
            ('spiderfoot-cli', dict(server_url=url, commands_file=domains, username='reader',
                                    password_file=resolvers, no_history=True),
             ['-s', url, '-e', domains, '-u', 'reader', '-P', resolvers, '-n', '-o', report]),
        ]
        for tool, settings, expected in cases:
            with self.subTest(tool=tool):
                rules = TOML_Loader(str(ROOT / 'config')).loadfile(f'scantool/{tool}.toml').dictionary
                validate_tool_config(tool, rules)
                rules['Defaults'].update(settings)
                dialog = self.form(tool, rules)
                dialog.fields[OUTPUT_KEYS[tool]].setText(self.temp.name)
                key = tool + '_default_output_filename'
                dialog.findChild(QLineEdit, key).setText(Path(report).name)
                self.assertIn(report, dialog.output_preview.text())
                dialog.request_execute()
                self.assertEqual(dialog.action, 'execute')
                module = ScanTool(tool, dialog.config, dialog.collect_values())
                self.assertEqual(module.build_command(), [tool, *expected])
                module.execute_properties['ScriptEnablers'][tool + '_enable'] = False
                with self.assertRaises(SystemExit):
                    module.build_command()

    def test_assetfinder_publishes_stdout_only_after_success(self):
        """Assetfinder publishes stdout on success and preserves the existing report on failure."""
        module = self.module('assetfinder', {0: 'lab.test'})
        report = Path(self.temp.name, 'assetfinder.txt')
        for status, data in [(0, b'www.lab.test\n'), (7, b'partial')]:
            def run(command, cwd, stdout):
                """Simulate an assetfinder subprocess writing to its stdout stream.

                Verify the native arguments, write the fixture bytes to stdout
                and return the exit status for this case.
                """
                self.assertEqual(command, ['assetfinder', '-subs-only', 'lab.test'])
                stdout.write(data)
                return status
            with patch('libasadt4.modules_main.subprocess.call', side_effect=run), self.assertRaises(SystemExit) as result:
                module.cmdgen()
            self.assertEqual(result.exception.code, status)
            self.assertEqual(report.read_bytes(), b'www.lab.test\n')
            self.assertEqual(list(report.parent.iterdir()), [report])

    def test_runtime_fields_are_local_to_each_tool_dialog(self):
        """Runtime Configuration edits apply only to the active dialog."""
        for tool in ('nmap', 'nikto', 'dnsrecon', 'msfpc'):
            with self.subTest(tool=tool):
                rules = self.module(tool).execute_properties
                key = tool + '_enable'
                rules['ScriptEnablers'][key] = 'False'
                dialog = self.form(tool, rules)
                self.assertEqual(dialog.navigation.item(dialog.navigation.count() - 1).text(), 'Runtime Config')
                switch = dialog.findChild(QCheckBox, key)
                self.assertFalse(switch.isChecked())
                switch.click()
                self.assertTrue(dialog.config['ScriptEnablers'][key])
                dialog.reject()
                self.assertEqual(rules['ScriptEnablers'][key], 'False')
                self.assertFalse(self.form(tool, rules).findChild(QCheckBox, key).isChecked())

    def test_nikto_runtime_validation_and_legacy_profile(self):
        """Nikto offers profile-specific report formats and identifies invalid runtime display codes."""
        rules = self.module('nikto').execute_properties
        del rules['ScriptEnablers']['nikto_cli_profile']
        rules['ScriptOutput']['nikto_default_output_format'] = 'nbe'
        dialog = self.form('nikto', rules)
        profile = dialog.findChild(QComboBox, 'nikto_cli_profile')
        formats = dialog.findChild(QComboBox, 'nikto_default_output_format')
        self.assertEqual(profile.currentText(), 'legacy')
        self.assertEqual(formats.currentText(), 'nbe')
        self.assertIn('nbe', formats.toolTip())
        profile.setCurrentText('current')
        self.assertEqual(formats.findText('nbe'), -1)
        self.assertNotIn('nbe', formats.toolTip())
        validate_tool_config('nikto', dialog.config)
        dialog.findChild(QLineEdit, 'nikto_displaytype').setText('invalid')
        with patch('libasadt4.displayboxhandler.QMessageBox.warning') as warning:
            dialog.request_execute()
        self.assertIn('nikto_displaytype', warning.call_args.args[2])
        self.assertEqual(dialog.navigation.currentItem().text(), 'Runtime Config')
        self.assertEqual(dialog.action, 'quit')

    def test_gui_debug_lines_clear_and_redraw_the_spinner(self):
        """Interactive debug output redraws the status spinner after writing a diagnostic."""
        import asadt
        from rich.console import Console

        output, trace = StringIO(), StringIO()
        options = dict(force_terminal=True, force_interactive=True, legacy_windows=False,
                       color_system=None, width=160, markup=False, highlight=False)
        stdout = Console(file=output, **options)
        stderr = Console(file=trace, **options)
        with patch.dict(os.environ, TERM='xterm'), \
             patch.object(asadt.modules_main, 'con_host', stdout), \
             patch.object(asadt.modules_main, 'debug_console', stderr), \
             patch.object(asadt, 'privilege_reasons', return_value=[]):
            QTimer.singleShot(0, lambda: QApplication.activeModalWidget().reject())
            with self.assertRaises(SystemExit) as result:
                asadt.asadtexec('scantool', 'nmap', debugger=True)
        self.assertEqual(result.exception.code, 1)
        self.assertRegex(trace.getvalue(), r'\r\x1b\[2K  \[debug\] GUI closed: quit\n[^\n]*Displaying UI\.\.\. scantool / nmap')
        self.assertNotIn('[debug]', output.getvalue())

    def test_run_uses_runtime_config_for_preview_and_command(self):
        """Nmap preview and execution use the per-run settings and preserve the saved TOML."""
        import asadt
        from typer.testing import CliRunner
        path = ROOT / 'config/scantool/nmap.toml'
        original = path.read_bytes()
        previews = []

        def fill_form():
            """Populate the active Nmap dialog during CLI dispatch.

            Edit runtime report settings and capture the preview before submitting the
            form to the mocked runner.
            """
            dialog = QApplication.activeModalWidget()
            dialog.fields[0].setText('127.0.0.1')
            dialog.fields[1].setText('80')
            dialog.fields[16].setCurrentText('TCP Connect Scan')
            dialog.fields[15].setText(self.temp.name)
            dialog.findChild(QCheckBox, 'nmap_assumesudoperms_enable').setChecked(False)
            dialog.findChild(QComboBox, 'nmap_fullscan_output_format').setCurrentText('oA')
            dialog.findChild(QLineEdit, 'nmap_fullscan_output_filename').setText('runtime-report')
            previews.append(dialog.output_preview.text())
            dialog.request_execute()

        QTimer.singleShot(0, fill_form)
        with patch('asadt.TypeCLI.confirm', return_value=True), \
             patch('libasadt4.modules_main.RunCommand', return_value=0) as run:
            result = CliRunner().invoke(asadt.cli_host, ['run', 'scantool', 'nmap', '--debugger'])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn('Script permissions:', result.stderr)
        self.assertIn("GUI TOOL_MODELS['nmap']", result.stderr)
        self.assertIn("[0] Target Address*: '127.0.0.1'", result.stderr)
        self.assertIn("ScriptOutput.nmap_fullscan_output_format: 'oA'", result.stderr)
        self.assertIn('ToolModule.__init__: ArgVerify active', result.stderr)
        self.assertLess(result.stderr.index('cmdgen -> build_command'), result.stderr.index('RunCommand: main scan'))
        self.assertIn('ArgVerify (nmap): required fields present', result.stderr)
        self.assertIn('NSE script expression defaulted to "not intrusive"', result.stderr)
        self.assertIn('ArgVerify (nmap): passed', result.stderr)
        self.assertIn('runtime-report.xml', previews[0])
        command = run.call_args.args[0]
        self.assertIn('--unprivileged', command)
        self.assertEqual(command[command.index('-oA') + 1], str(Path(self.temp.name, 'runtime-report')))
        self.assertEqual(path.read_bytes(), original)

    def test_gui_output_directory_creation_and_errors(self):
        """Directory creation, refusal and filesystem errors produce the expected form state."""
        from PySide6.QtWidgets import QMessageBox
        for name, key in OUTPUT_KEYS.items():
            dialog = self.form(name)
            dialog.fields[0].setText('127.0.0.1')
            if name == 'massdns':
                for index, source in enumerate(self.massdns_inputs()):
                    dialog.fields[index].setText(source)
            if name == 'nmap':
                dialog.fields[1].setText('80')
                dialog.fields[16].setCurrentText('TCP Connect Scan')
            output = Path(self.temp.name, name)
            dialog.fields[key].setText(str(output))
            with patch('libasadt4.displayboxhandler.QMessageBox.question', return_value=QMessageBox.StandardButton.No):
                dialog.request_execute()
            self.assertEqual(dialog.action, 'quit')
            self.assertFalse(output.exists())
            with patch('libasadt4.displayboxhandler.QMessageBox.question', return_value=QMessageBox.StandardButton.Yes):
                dialog.request_execute()
            self.assertTrue(output.is_dir())
            self.assertEqual(dialog.action, 'execute')
        dialog = self.form('nikto')
        dialog.fields[0].setText('127.0.0.1')
        output = Path(self.temp.name, 'file.txt')
        output.touch()
        dialog.fields[19].setText(str(output))
        with patch('libasadt4.displayboxhandler.QMessageBox.warning') as warning:
            dialog.request_execute()
        warning.assert_called_once()
        self.assertEqual(dialog.action, 'quit')

    def test_gui_opt_out_and_debug_redaction(self):
        """Disabling verification for one dialog preserves credential redaction and the next dialog's default."""
        import asadt
        from typer.testing import CliRunner

        def fill_form():
            """Submit sensitive Nikto fields with ArgVerify disabled.

            Drive the active modal form so the test can compare redacted diagnostics
            with actual subprocess arguments.
            """
            dialog = QApplication.activeModalWidget()
            dialog.fields[0].setText('localhost')
            dialog.fields[15].setText('proxy-secret')
            dialog.fields[17].setText('auth-secret')
            dialog.fields[18].setText('key-secret')
            dialog.fields[19].setText(self.temp.name)
            dialog.verify_arguments.setChecked(False)
            dialog.request_execute()

        QTimer.singleShot(0, fill_form)
        with patch('libasadt4.modules_main.ArgVerify') as verify, \
             patch('libasadt4.modules_main.subprocess.call', return_value=0) as run:
            result = CliRunner().invoke(asadt.cli_host, ['run', 'scantool', 'nikto', '--debugger'])
        self.assertEqual(result.exit_code, 0, result.output)
        verify.assert_not_called()
        self.assertIn('ArgVerify disabled', result.stderr)
        self.assertIn('[17] Host Credentials: <redacted>', result.stderr)
        for secret in ('proxy-secret', 'auth-secret', 'key-secret'):
            self.assertIn(secret, run.call_args.args[0])
            self.assertNotIn(secret, result.stderr)
        self.assertTrue(self.form('nikto').verify_arguments.isChecked())

    def test_overwrite_rechecks_all_formats_at_submit(self):
        """Nmap requests consent for existing oA report files when the form is submitted."""
        from PySide6.QtWidgets import QMessageBox
        config = self.module('nmap').execute_properties
        config['ScriptEnablers'].update(nmap_updatensedb=False, nmap_assumesudoperms_enable=False)
        config['ScriptOutput'].update(nmap_fullscan_output_format='oA', nmap_fullscan_output_filename='scan')
        dialog = self.form('nmap', config)
        dialog.fields[0].setText('localhost')
        dialog.fields[1].setText('80')
        dialog.fields[16].setCurrentText('TCP Connect Scan')
        dialog.fields[15].setText(self.temp.name)
        for suffix in ('.xml', '.gnmap'):
            Path(self.temp.name, 'scan' + suffix).touch()
        with patch.object(QMessageBox, 'question', return_value=QMessageBox.StandardButton.No) as question:
            dialog.request_execute()
            self.assertEqual(dialog.action, 'quit')
            message = question.call_args.args[2]
            self.assertIn(str(Path(self.temp.name, 'scan.xml')), message)
            self.assertIn(str(Path(self.temp.name, 'scan.gnmap')), message)
            self.assertNotIn('scan.nmap', message)
            question.return_value = QMessageBox.StandardButton.Yes
            dialog.request_execute()
            self.assertEqual(dialog.action, 'execute')

    def test_msfpc_warns_for_nonempty_directory(self):
        """MSFPC requests consent for a nonempty directory and leaves the form open on refusal."""
        from PySide6.QtWidgets import QMessageBox
        dialog = self.form('msfpc')
        dialog.fields[0].setText('localhost')
        dialog.fields[27].setText(self.temp.name)
        Path(self.temp.name, 'existing payload').touch()
        with patch.object(QMessageBox, 'question', return_value=QMessageBox.StandardButton.No) as question:
            dialog.request_execute()
        self.assertIn(self.temp.name, question.call_args.args[2])
        self.assertEqual(dialog.action, 'quit')

    @patch('libasadt4.displayboxhandler.os.geteuid', return_value=1000, create=True)
    def test_nmap_privilege_warning_matches_request(self, uid):
        """Nmap privilege warnings reflect the scan method, database access and effective privileges."""
        from PySide6.QtWidgets import QMessageBox
        dialog = self.form('nmap')
        for key, value in ((0, 'localhost'), (1, '80'), (15, self.temp.name)):
            dialog.fields[key].setText(value)
        dialog.fields[16].setCurrentText('TCP Connect Scan')
        dialog.config = self.module('nmap').execute_properties
        dialog.config['ScriptEnablers']['nmap_updatensedb'] = 'True'
        dialog.config['ScriptEnablers']['nmap_assumesudoperms_enable'] = 'False'
        scripts = Path(self.temp.name, 'scripts')
        scripts.mkdir()
        database = scripts / 'script.db'
        database.touch()
        allowed = os.access
        with patch.dict(os.environ, NMAPDIR=self.temp.name), \
             patch('os.access', side_effect=lambda path, mode: path != database and allowed(path, mode)), \
             patch.object(QMessageBox, 'warning', return_value=QMessageBox.StandardButton.No) as warning:
            dialog.request_execute()
            self.assertIn(str(database), warning.call_args.args[2])
            self.assertEqual(dialog.action, 'quit')
            warning.return_value = QMessageBox.StandardButton.Yes
            dialog.request_execute()
            self.assertEqual(dialog.action, 'execute')
        dialog.config['ScriptEnablers']['nmap_updatensedb'] = 'False'
        self.assertEqual(dialog.privilege_warning(dialog.collect_values()), '')
        dialog.fields[16].setCurrentText('TCP SYN Scan')
        self.assertIn('TCP SYN Scan', dialog.privilege_warning(dialog.collect_values()))
        for tool in ('dnsrecon', 'nikto', 'msfpc'):
            self.assertEqual(self.form(tool).privilege_warning({}), '')
        uid.return_value = 0
        self.assertEqual(dialog.privilege_warning(dialog.collect_values()), '')

    def test_nmap_preliminary_failures_stop_execution(self):
        """Nmap stops at the first failed preliminary command and propagates its status."""
        for results, calls in (([9], 1), ([0, 7], 2)):
            module = self.module('nmap', {4: True})
            with patch('libasadt4.modules_main.RunCommand', side_effect=results) as run:
                with self.assertRaises(SystemExit) as result:
                    module.cmdgen()
            self.assertEqual(result.exception.code, results[-1])
            self.assertEqual(run.call_count, calls)

    def test_dnsrecon_modes_formats_and_optional_arguments(self):
        """DNSRecon maps the selected mode, report format and optional fields to native arguments."""
        dialog = self.form('dnsrecon')
        self.assertEqual(dialog.collect_values(), {0: '', 1: ['Standard'], 2: '', 3: False, 4: '',
                                                  5: ['JSON'], 6: 0, 7: 0})
        directory = Path(self.temp.name, 'DNS reports')
        directory.mkdir()
        dialog.fields[0].setText('lab.test')
        dialog.fields[4].setText(str(directory))
        for index, (mode, flag, suffix) in enumerate((('std', '-j', 'json'), ('srv', '-c', 'csv'), ('caa', '-x', 'xml'))):
            dialog.fields[1].setCurrentIndex(index)
            dialog.fields[5].setCurrentIndex(index)
            dialog.fields[2].setText('127.0.0.1' if index else '')
            dialog.fields[3].setChecked(bool(index))
            module = self.module('dnsrecon', dialog.collect_values())
            options = ['-n', '127.0.0.1', '--tcp'] if index else []
            expected = ['dnsrecon', '-d', 'lab.test', '-t', mode, *options, flag, str(directory / f'dnsrecon.{suffix}')]
            with patch('libasadt4.modules_main.subprocess.call', return_value=7) as call:
                with self.assertRaises(SystemExit) as result:
                    module.cmdgen()
            call.assert_called_once_with(expected, cwd=None)
            self.assertEqual(result.exception.code, 7)

    def test_directory_preview_and_format_changes(self):
        """The report preview reflects directory contents and changes to the DNSRecon format."""
        directory = Path(self.temp.name, 'reports')
        dialog = self.form('dnsrecon')
        dialog.fields[4].setText(str(directory))
        self.assertIn('will be created', dialog.output_preview.text())
        self.assertFalse(directory.exists())
        directory.mkdir()
        dialog.refresh_output_preview()
        self.assertIn('Directory is empty.', dialog.output_preview.text())
        self.assertIn(f'Planned file: {directory / "dnsrecon.json"}', dialog.output_preview.text())
        report = directory / 'dnsrecon.csv'
        report.touch()
        dialog.fields[5].setCurrentText('CSV')
        self.assertIn('already contains', dialog.output_preview.text())
        self.assertIn(f'Already exists: {report}', dialog.output_preview.text())
        dialog.fields[4].clear()
        self.assertNotIn('dnsrecon.csv', dialog.output_preview.text())

    def test_nmap_all_formats_preview(self):
        """Nmap oA previews all three output paths under the configured basename."""
        dialog = self.form('nmap')
        dialog.config = {'ScriptOutput': {'nmap_fullscan_output_filename': 'custom',
                                         'nmap_fullscan_output_format': 'oA'}}
        dialog.fields[15].setText(self.temp.name)
        for suffix in ('.nmap', '.xml', '.gnmap'):
            self.assertIn(str(Path(self.temp.name, 'custom' + suffix)), dialog.output_preview.text())

    def test_dnsrecon_required_fields_and_disabled_tool(self):
        """Incomplete DNSRecon submissions exit with status 3 and disabled runners exit with status 1."""
        for key in (0, 4):
            with self.assertRaises(SystemExit) as result:
                self.module('dnsrecon', {key: ''})
            self.assertEqual(result.exception.code, 3)
        module = self.module('dnsrecon')
        module.execute_properties['ScriptEnablers']['dnsrecon_enable'] = 'False'
        with patch('libasadt4.modules_main.RunCommand') as run:
            with self.assertRaises(SystemExit) as result:
                module.cmdgen()
        self.assertEqual(result.exception.code, 1)
        run.assert_not_called()

    def test_nmap_zero_timing_and_spaced_output(self):
        """Nmap preserves -T0 and spaces within a report path argument."""
        module = self.module('nmap', {8: 0, 15: self.temp.name + '/output folder'}, verify=False)
        command = module.build_command()
        self.assertIn('-T0', command)
        self.assertEqual(os.path.normpath(command[command.index('-oN') + 1]),
                         os.path.join(self.temp.name, 'output folder', 'nmap-fullscan_output.txt'))
        self.assertIn('-sS', command)

    def test_all_scan_methods(self):
        """Each Nmap scan method maps to its native switch."""
        dialog = self.form('nmap')
        expected = ['-sS', '-sT', '-sA', '-sW', '-sM', '-sU', '-sN', '-sF', '-sX']
        for index, flag in enumerate(expected):
            dialog.fields[16].setCurrentIndex(index)
            module = self.module('nmap', {16: dialog.collect_values()[16]})
            self.assertIn(flag, module.build_command())

    def test_nmap_limits_and_script_file_without_tracing(self):
        """Nmap shares limits across scans and accepts an NSE argument file with tracing disabled."""
        module = self.module('nmap', {3: 'script args.txt', 4: True, 17: 15, 18: 100})
        enablers = module.execute_properties['ScriptEnablers']
        enablers['nmap_nsedebug_enable'] = False
        limits = ['--host-timeout', '15m', '--max-rate', '100']
        with patch('libasadt4.modules_main.RunCommand', return_value=0) as run:
            with self.assertRaises(SystemExit):
                module.cmdgen()
        trace, main = [call.args[0] for call in run.call_args_list]
        self.assertEqual(trace, ['nmap', '--traceroute', *limits, '127.0.0.1'])
        self.assertEqual(main[main.index('--host-timeout'):][:4], limits)
        self.assertEqual(main[main.index('--script-args-file') + 1], 'script args.txt')
        self.assertNotIn('--script-trace', main)
        enablers['nmap_nsescriptscan_enable'] = 'False'
        self.assertNotIn('--script-args-file', module.build_command())

    def test_legacy_argument_containers_pick_up_defaults(self):
        """The runner applies new TOML defaults to a copy of a 17-field Nmap submission."""
        module = self.module('nmap')
        rules = module.execute_properties
        rules['Defaults'] = {'max_rate': 75}
        old = {key: module.execute_arguments[key] for key in range(17)}
        for values in (old, list(old.values())):
            command = ScanTool('nmap', rules, values).build_command()
            self.assertEqual(command[command.index('--max-rate') + 1], '75')
            self.assertNotIn('--host-timeout', command)
            self.assertEqual(len(values), 17)

    def test_nikto_profile_and_scan_options(self):
        """Nikto profiles determine cookie flags and report formats, and scan limits use native units."""
        module = self.module('nikto', {20: 900, 21: '/staff portal'})
        rules = module.execute_properties
        current = self.form('nikto', rules)
        self.assertTrue(current.fields[7].isChecked())
        command = module.build_command()
        self.assertIn('-nocookies', command)
        self.assertEqual(command[command.index('-root') + 1], '/staff portal')
        self.assertEqual(command[command.index('-maxtime') + 1], '900s')
        module.execute_arguments[7] = True
        self.assertNotIn('-nocookies', module.build_command())
        del rules['ScriptEnablers']['nikto_cli_profile']
        self.assertFalse(self.form('nikto', rules).fields[7].isChecked())
        self.assertIn('-usecookies', module.build_command())
        rules['ScriptOutput']['nikto_default_output_format'] = 'nbe'
        validate_tool_config('nikto', rules)
        rules['ScriptEnablers']['nikto_cli_profile'] = 'current'
        with self.assertRaisesRegex(ValueError, 'nikto_default_output_format'):
            validate_tool_config('nikto', rules)

    def test_dns_defaults_and_per_run_overrides(self):
        """DNSRecon runtime overrides update the preview, worker control and native arguments."""
        module = self.module('dnsrecon')
        rules = module.execute_properties
        rules['Defaults'] = {'dns_server': '192.0.2.1,192.0.2.2', 'report_format': 'CSV',
                             'lifetime_seconds': 7, 'threads': 8}
        rules['ScriptOutput']['dnsrecon_default_output_filename'] = 'zone inventory.json'
        form = self.form('dnsrecon', rules)
        form.fields[0].setText('example.test')
        form.fields[4].setText(self.temp.name)
        self.assertIn('zone inventory.csv', form.output_preview.text())
        for mode in ('Standard', 'Service Records', 'Certificate Authority Records'):
            form.fields[1].setCurrentText(mode)
            command = ScanTool('dnsrecon', rules, form.collect_values()).build_command()
            threaded = mode != 'Certificate Authority Records'
            self.assertEqual(form.fields[7].isEnabled(), threaded)
            self.assertEqual('--threads' in command, threaded)
            self.assertEqual(command[command.index('--lifetime') + 1], '7')
            self.assertEqual(command[command.index('-n') + 1], rules['Defaults']['dns_server'])
        form.fields[2].clear()
        form.fields[5].setCurrentText('XML')
        form.findChild(QLineEdit, 'dnsrecon_default_output_filename').setText('custom')
        self.assertIn('custom.xml', form.output_preview.text())
        command = ScanTool('dnsrecon', form.config, form.collect_values()).build_command()
        self.assertNotIn('-n', command)
        self.assertEqual(command[-2:], ['-x', str(Path(self.temp.name, 'custom.xml'))])
        self.assertEqual(rules['ScriptOutput']['dnsrecon_default_output_filename'], 'zone inventory.json')
        self.assertEqual(rules['Defaults']['report_format'], 'CSV')

    def test_msfpc_mode_changes_preserve_inactive_values(self):
        """MSFPC restores prior single-output choices after switching through batch and loop modes."""
        form = self.form('msfpc')
        form.fields[7].setChecked(True)
        for mode, console in ((25, False), (26, True)):
            form.fields[mode].setChecked(True)
            self.assertEqual(form.fields[11].isEnabled(), console)
            for key in (2, 5, 7, 12):
                self.assertFalse(form.fields[key].isEnabled())
            self.assertTrue(form.fields[0].isEnabled())
            self.assertTrue(form.fields[1].isEnabled())
        form.groups['ss_type'].buttons()[0].setChecked(True)
        self.assertTrue(form.fields[7].isEnabled())
        self.assertTrue(form.fields[7].isChecked())

    def test_bad_tool_settings_stop_before_gui(self):
        """Invalid tool settings identify the TOML file and key before the form opens."""
        import asadt
        config = Path(self.temp.name)
        (config / 'scantool').mkdir()
        (config / 'scriptinfo.toml').write_bytes((ROOT / 'config/scriptinfo.toml').read_bytes())
        source = (ROOT / 'config/scantool/dnsrecon.toml').read_text(encoding='utf-8')
        for old, new, key in [('dnsrecon_enable = true', 'dnsrecon_enable = 1', 'ScriptEnablers.dnsrecon_enable'),
                              ("'JSON'", "'PDF'", 'Defaults.report_format'),
                              ('threads = 0', 'threads = -1', 'Defaults.threads')]:
            (config / 'scantool/dnsrecon.toml').write_text(source.replace(old, new), encoding='utf-8')
            with patch.object(asadt, 'local_config_dir', self.temp.name), \
                 patch.object(asadt.con_host, 'print') as output, \
                 patch('libasadt4.displayboxhandler.DisplayBoxHandler_Service') as gui:
                with self.assertRaises(SystemExit) as result:
                    asadt.asadtexec('scantool', 'dnsrecon')
                self.assertEqual(result.exception.code, 3)
                self.assertIn('dnsrecon.toml', str(output.call_args.args[0]))
                self.assertIn(key, str(output.call_args.args[0]))
                gui.assert_not_called()

    def test_apt_uses_configured_packages_and_rejects_arguments(self):
        """APT receives the configured package list and rejects invalid entries before launch."""
        import asadt
        config = TOML_Loader(str(ROOT / 'config')).loadfile('scriptinfo.toml')
        with patch('asadt.load_main_config', return_value=config), \
             patch('libasadt4.mainprog.os.geteuid', create=True, return_value=0), \
             patch('libasadt4.mainprog.subprocess.call', return_value=0) as call:
            config.dictionary['APT_DEP']['dependency_list'] = ['dnsrecon']
            with self.assertRaises(SystemExit) as result:
                asadt.hostupdate(True)
            self.assertEqual(result.exception.code, 0)
            self.assertEqual(call.call_args.args[0], ['apt', 'install', '-y', 'dnsrecon'])
            for bad in (['-o'], ['nmap-'], 'nikto', [], {'scantool': 'nmap'}):
                call.reset_mock()
                config.dictionary['APT_DEP']['dependency_list'] = bad
                with self.assertRaises(SystemExit) as result:
                    asadt.hostupdate(True)
                self.assertEqual(result.exception.code, 3)
                call.assert_not_called()

    def test_nikto_disabled_is_not_truthy_string(self):
        """Nikto treats the legacy string 'False' as disabled and exits with status 1."""
        module = self.module('nikto')
        module.execute_properties['ScriptEnablers']['nikto_enable'] = 'False'
        with self.assertRaises(SystemExit) as result:
            module.build_command()
        self.assertEqual(result.exception.code, 1)

    def test_nikto_useragent_has_value(self):
        """Nikto passes the complete user agent as the argument following -useragent."""
        command = self.module('nikto', {6: 'ASADT Test Agent'}).build_command()
        self.assertEqual(command[command.index('-useragent') + 1], 'ASADT Test Agent')

    def test_msfpc_loop_uses_address_and_port(self):
        """MSFPC loop mode receives the address and port in native argument order."""
        command = self.module('msfpc', {25: True, 1: '4444'}).build_command()
        self.assertEqual(command, ['msfpc', 'loop', '127.0.0.1', '4444'])

    def test_msfpc_default_and_batch(self):
        """MSFPC single and batch modes produce the expected positional arguments."""
        self.assertEqual(self.module('msfpc').build_command(),
                         ['msfpc', 'windows', '127.0.0.1', 'msf', 'reverse', 'staged', 'tcp'])
        self.assertEqual(self.module('msfpc', {26: True}).build_command(),
                         ['msfpc', 'msf', 'batch', '127.0.0.1'])

    def test_msfpc_checks_only_options_used_in_selected_mode(self):
        """MSFPC validates active options and identifies incompatible single-output choices by field key."""
        valid_bash = {24: False, 15: True, 11: False, 10: True}
        self.assertIn('sh', self.module('msfpc', valid_bash).build_command())
        for edits, key in (({2: True, 3: False, 6: False, 8: True}, 6),
                           ({24: False, 15: True}, 10),
                           ({24: False, 18: True}, 5),
                           ({24: False, 20: True, 11: False, 10: True}, 11),
                           ({25: True, 26: True}, 25)):
            with self.subTest(edits=edits), self.assertRaises(SystemExit) as failure:
                self.module('msfpc', edits)
            self.assertEqual(failure.exception.issue.key, key)
        inactive = {2: True, 3: True, 15: True, 24: True}
        for key, mode in ((25, 'loop'), (26, 'batch')):
            self.assertIn(mode, self.module('msfpc', {**inactive, key: True}).build_command())

    def test_list_verification_points_to_the_file_and_line(self):
        """List-file errors identify the field and line before directory creation and allow a corrected retry."""
        domains, resolvers = map(Path, self.massdns_inputs())
        domains.write_text('_sip._tcp.example.test.\n*.example.test\n')
        resolvers.write_text('192.0.2.53:5353\n[2001:db8::53]:53\n2001:db8::54\n')
        rules = TOML_Loader(ROOT / 'config').loadfile('scantool/massdns.toml').dictionary
        values = self.form('massdns', rules).collect_values()
        output = Path(self.temp.name, 'unchecked-output')
        values.update({0: str(domains), 1: str(resolvers), OUTPUT_KEYS['massdns']: str(output)})
        with patch('libasadt4.modules_main.Prompt.ask', return_value='y') as prompt:
            for path, key, contents in ((domains, 0, 'example.test\nbad..test\n'),
                                        (resolvers, 1, '192.0.2.53\n[::1]:70000\n')):
                previous = path.read_bytes()
                path.write_text(contents)
                with self.assertRaises(SystemExit) as failure:
                    ScanTool('massdns', rules, values)
                self.assertEqual(failure.exception.issue.key, key)
                self.assertIn('line 2', str(failure.exception.issue))
                path.write_bytes(previous)
            prompt.assert_not_called()
            self.assertFalse(output.exists())
            self.assertIn(str(domains), ScanTool('massdns', rules, values).build_command())
        wordlist = Path(self.temp.name, 'inputs')
        for tool, key, contents in (('dirb', 1, b'# empty\n'), ('dirb', 1, b'admin\n\0exe\n'),
                                    ('dnsmap', 1, b'www\nbad label\n'), ('nikto', 0, b'localhost\n999.0.0.5\n')):
            wordlist.write_bytes(contents)
            with self.subTest(tool=tool), self.assertRaises(SystemExit) as failure:
                self.module(tool, {key: str(wordlist)})
            self.assertEqual(failure.exception.issue.key, key)

    def test_shell_metacharacters_remain_one_argument(self):
        """Bypassed verification preserves shell metacharacters within one subprocess argument."""
        target = '127.0.0.1; echo unexpected $(whoami)'
        for name in ('nmap', 'nikto', 'msfpc'):
            with self.assertRaises(SystemExit) as result:
                self.module(name, {0: target})
            self.assertEqual(result.exception.code, 3)
            module = self.module(name, {0: target}, verify=False)
            command = module.build_command()
            self.assertIn(target, command)
            with patch('libasadt4.modules_main.subprocess.call', return_value=0) as call:
                self.assertEqual(RunCommand(command), 0)
            call.assert_called_once_with(command, cwd=None)

    def test_execution_return_code_and_cwd(self):
        """The runner propagates child status and applies the output directory only to the child."""
        module = self.module('msfpc')
        original = os.getcwd()
        with patch('libasadt4.modules_main.subprocess.call', return_value=7) as call:
            with self.assertRaises(SystemExit) as result:
                module.cmdgen()
        self.assertEqual(result.exception.code, 7)
        self.assertEqual(call.call_args.kwargs, {'cwd': self.temp.name})
        self.assertEqual(os.getcwd(), original)

    def test_missing_executable(self):
        """A missing executable returns status 127."""
        with patch('libasadt4.modules_main.subprocess.call', side_effect=FileNotFoundError('missing')):
            self.assertEqual(RunCommand(['missing']), 127)

    def test_debug_mode_without_verification(self):
        """Debug output redacts credentials and records elapsed time and status with verification disabled."""
        module = self.module('nikto', {17: 'user:secret'}, verify=False)
        module.execute_debugger = True
        trace = StringIO()
        with redirect_stderr(trace), patch('libasadt4.modules_main.subprocess.call', return_value=0) as call:
            with self.assertRaises(SystemExit) as result:
                module.cmdgen()
        self.assertEqual(result.exception.code, 0)
        self.assertIn('user:secret', call.call_args.args[0])
        self.assertNotIn('user:secret', trace.getvalue())
        self.assertIn("  [debug] argv=[\n  [debug]   'nikto',\n", trace.getvalue())
        self.assertIn("  [debug]   '-id',\n  [debug]   '<redacted>'", trace.getvalue())
        self.assertIn(f'cwd={os.getcwd()!r}', trace.getvalue())
        self.assertIn('nikto exit=0 elapsed=', trace.getvalue())

    def test_input_snapshot_is_not_mutated(self):
        """Nmap fills a blank NSE selector in the working copy and preserves the submitted field."""
        module = self.module('nmap')
        self.assertEqual(module.verified_input.preagverify[2], '')
        self.assertEqual(module.execute_arguments[2], 'not intrusive')

    def test_verification_trace_normalization_failures_and_privacy(self):
        """Verification traces report defaults, normalization and failures while protecting sensitive values."""
        module = self.module('nikto', {17: 'user:secret', 15: 'proxy-secret'}, verify=False)
        values = {**module.execute_arguments, 13: 7.5}
        del values[20]

        def verify(**options):
            """Construct the runner with the enclosing test's values and trace options.

            Pass the supplied keyword options into the runner so the same submission can
            exercise verified and bypassed paths.
            """
            return ScanTool('nikto', module.execute_properties, values, **options)

        trace = StringIO()
        with redirect_stderr(trace):
            verify()
        self.assertEqual(trace.getvalue(), '')
        with redirect_stderr(trace):
            verify(show_debug=True)
        self.assertIn('applied default', trace.getvalue())
        self.assertIn('normalized 7.5 to 7 within 1..100', trace.getvalue())
        values[13] = 'invalid-secret'
        with redirect_stderr(trace), self.assertRaises(SystemExit) as result:
            verify(show_debug=True)
        self.assertEqual(result.exception.code, 3)
        self.assertIn('failed: Request Timeout (Seconds): expected a whole number', trace.getvalue())
        with redirect_stderr(trace):
            verify(show_debug=True, ioverify=False)
        self.assertIn('skipped (ioverify=False)', trace.getvalue())
        for secret in ('user:secret', 'proxy-secret', 'invalid-secret'):
            self.assertNotIn(secret, trace.getvalue())

    def test_invalid_slider_stops_before_output_prompt(self):
        """An invalid slider value rejects the submission before the directory creation prompt."""
        module = self.module('nmap')
        output = Path(self.temp.name, 'new-directory')
        for timing in (99, -0.5, 5.9, 'fast', True, float('nan'), float('inf')):
            values = {**module.execute_arguments, 8: timing, 15: str(output)}
            with self.subTest(timing=timing), patch('libasadt4.modules_main.Prompt.ask') as prompt, \
                 patch('libasadt4.modules_main.con_host.print') as message, self.assertRaises(SystemExit) as result:
                ScanTool('nmap', module.execute_properties, values)
            self.assertEqual(result.exception.code, 3)
            self.assertIn('Scan Timing Preset: expected a whole number from 0 to 5', str(message.call_args.args[0]))
            prompt.assert_not_called()
        self.assertFalse(output.exists())

    def test_legacy_sliders_normalize_without_changing_input(self):
        """Legacy sliders normalize in the working copy and invalid values exit with status 3."""
        for tool, key, value in (('nmap', 8, 3.75), ('nikto', 13, 7.5)):
            with self.subTest(tool=tool):
                module = self.module(tool, {key: value})
                self.assertEqual(module.verified_input.preagverify[key], value)
                self.assertEqual(module.execute_arguments[key], int(value))
        with self.assertRaises(SystemExit) as result:
            self.module('nmap', {17: 3.75})
        self.assertEqual(result.exception.code, 3)

    def test_gui_and_direct_call_report_same_required_fields(self):
        """Qt and direct verification report the same missing required fields."""
        for tool in OUTPUT_KEYS:
            with self.subTest(tool=tool):
                dialog = self.form(tool)
                with patch('libasadt4.displayboxhandler.QMessageBox.warning') as warning:
                    dialog.request_execute()
                values = dialog.collect_values()
                del values[OUTPUT_KEYS[tool]]
                with patch('libasadt4.modules_main.con_host.print') as message:
                    result = ArgVerify(values, tool, None).input_verification()
                self.assertTrue(result.requires_exit)
                self.assertEqual(str(message.call_args.args[0]).strip(), warning.call_args.args[2])

    def test_directory_creation_failure_stops_execution(self):
        """A directory creation failure marks verification as failed after the user approves creation."""
        module = self.module('nikto')
        values = module.execute_arguments.copy()
        values[19] = self.temp.name + '/missing'
        with patch('libasadt4.modules_main.Prompt.ask', return_value='y'), \
             patch('libasadt4.output_paths.Path.mkdir', side_effect=PermissionError('denied')):
            result = ArgVerify(values, 'nikto', module.execute_properties).input_verification()
        self.assertTrue(result.requires_exit)

    def test_config_editor_preserves_path_and_permissions(self):
        """The editor receives the complete path and requested line and preserves permissions by default."""
        filename = self.temp.name + '/my config.toml'
        with patch('libasadt4.mainprog.subprocess.call', return_value=0) as call, \
             patch('libasadt4.mainprog.os.chmod') as chmod:
            with self.assertRaises(SystemExit):
                CnfEdit(5).run_editor(filename)
        call.assert_called_once_with(['nano', '-l', '-L', '+5', filename])
        chmod.assert_not_called()

    def test_cnfedit_banner_picker_and_missing_editor_fallback(self):
        """The CLI opens the selected file in a fallback editor and propagates its status."""
        import asadt
        from typer.testing import CliRunner
        path = Path(self.temp.name, 'broken config.toml')
        path.write_text('invalid TOML')
        with patch('asadt.local_config_dir', self.temp.name), \
             patch('libasadt4.mainprog.subprocess.call', side_effect=[FileNotFoundError(), 7]) as launch:
            runner = CliRunner()
            self.assertNotIn('nanoedit', runner.invoke(asadt.cli_host, ['--help']).output)
            result = runner.invoke(asadt.cli_host, ['cnfedit'], input='1\n')
        self.assertIn('CnfEdit', result.output)
        self.assertIn(path.name, result.output)
        self.assertEqual(result.exit_code, 7, result.output)
        self.assertEqual([call.args[0] for call in launch.call_args_list],
                         [['nano', '-l', '-L', '+5', str(path)], ['vim', '+5', str(path)]])

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() != 0, 'requires an unprivileged POSIX user')
    def test_read_only_report_and_directory_keep_form_open(self):
        """Read-only output permissions prevent submission and preserve the existing report."""
        dialog = self.form('dnsrecon')
        dialog.fields[0].setText('lab.test')
        dialog.fields[4].setText(self.temp.name)
        report = Path(self.temp.name, 'dnsrecon.json')
        report.write_text('previous report')
        report.chmod(0o444)
        with patch('libasadt4.displayboxhandler.QMessageBox.warning') as warning:
            dialog.request_execute()
            self.assertIn(str(report), warning.call_args.args[2])
            self.assertEqual(dialog.action, 'quit')
        with self.assertRaises(SystemExit):
            self.module('dnsrecon')
        self.assertEqual(report.read_text(), 'previous report')
        directory = Path(self.temp.name)
        directory.chmod(0o555)
        self.addCleanup(directory.chmod, 0o700)
        with patch('libasadt4.displayboxhandler.QMessageBox.warning') as warning:
            dialog.request_execute()
            self.assertEqual(warning.call_args.args[2], f'Cannot write to this path: {directory}')

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() != 0, 'requires an unprivileged POSIX user')
    def test_read_only_config_and_download(self):
        """A protected configuration can be viewed, and a failed write preserves the destination."""
        path = Path(self.temp.name, 'protected.toml')
        path.write_text('original')
        path.chmod(0o444)
        with patch('libasadt4.mainprog.subprocess.call', return_value=0) as call:
            with self.assertRaises(SystemExit) as result:
                CnfEdit(5).run_editor(str(path))
            self.assertEqual(result.exception.code, 1)
            call.assert_not_called()
            with self.assertRaises(SystemExit) as result:
                CnfEdit(5, read_only=True).run_editor(str(path))
            self.assertEqual(result.exception.code, 0)
            call.assert_called_once()
        with self.assertRaises(SystemExit):
            ProgUpdate.save_download(path, None)
        self.assertEqual(path.read_text(), 'original')

    def test_toml_errors_are_reported(self):
        """Missing and malformed TOML files both set the loader's status_ok flag to False."""
        loader = TOML_Loader(self.temp.name).loadfile('missing.toml')
        self.assertFalse(loader.status_ok)
        Path(self.temp.name, 'bad.toml').write_text('not valid toml')
        self.assertFalse(loader.loadfile('bad.toml').status_ok)

    def test_download_preserves_previous_file_on_write_failure(self):
        """A failed download replacement preserves the destination and cleans up before retry."""
        path = Path(self.temp.name, 'release.zip')
        path.write_bytes(b'previous')
        with patch('libasadt4.mainprog.requests.get') as get:
            response = get.return_value
            response.iter_content.return_value = [b'new', b' release']
            with patch('libasadt4.mainprog.os.replace', side_effect=PermissionError('denied')):
                with self.assertRaises(SystemExit):
                    ProgUpdate.save_download(path, response)
            self.assertEqual(path.read_bytes(), b'previous')
            self.assertEqual(list(path.parent.iterdir()), [path])
            ProgUpdate.save_download(path, response)
            self.assertEqual(path.read_bytes(), b'new release')

    @patch('libasadt4.mainprog.subprocess.call', return_value=0)
    @patch('libasadt4.mainprog.os.geteuid', return_value=1000, create=True)
    def test_apt_update_requires_root_before_launch(self, uid, call):
        """APT requires root and installs packages from the legacy registry after a successful update."""
        toolbox = {'scantool': 'nmap dnsrecon', 'hacktool': 'msfpc'}
        with self.assertRaises(SystemExit) as result:
            ProgUpdate.localdebupdate(toolbox)
        self.assertEqual(result.exception.code, 1)
        call.assert_not_called()
        uid.return_value = 0
        ProgUpdate.localdebupdate(toolbox)
        self.assertEqual([item.args[0] for item in call.call_args_list],
                         [['apt', 'update'], ['apt', 'install', '-y', 'nmap', 'dnsrecon', 'msfpc']])

    def test_update_http_has_timeout(self):
        """The release metadata request uses a 30-second timeout."""
        with patch('libasadt4.mainprog.requests.get') as get:
            ProgUpdate('v4.0.1', 'https://example.test/scriptinfo.toml')
        get.assert_called_once_with('https://example.test/scriptinfo.toml', timeout=30)

    @patch('libasadt4.privileges.os.geteuid', return_value=1000, create=True)
    def test_terminal_prompt_precedes_gui_and_covers_only_acknowledged_options(self, uid):
        """The CLI obtains privilege consent before opening Qt, and new options receive a separate warning."""
        import asadt
        with patch('libasadt4.displayboxhandler.DisplayBoxHandler_Service') as service, \
             patch('asadt.TypeCLI.confirm', return_value=False) as confirm:
            with self.assertRaises(SystemExit):
                asadt.asadtexec('scantool', 'nmap')
            confirm.assert_called_once()
            service.assert_not_called()
            confirm.return_value = True
            with self.assertRaises(SystemExit):
                asadt.asadtexec('scantool', 'nmap')
            name, config, acknowledged = service.return_value.DISPLAY_UI_MODEL.call_args.args
            dialog = self.form(name)
            dialog.config = config
            dialog.acknowledged = acknowledged
            self.assertEqual(dialog.privilege_warning(dialog.collect_values()), '')
            dialog.fields[6].setChecked(True)
            self.assertIn('OS detection', dialog.privilege_warning(dialog.collect_values()))
            confirm.reset_mock()
            with self.assertRaises(SystemExit):
                asadt.asadtexec('scantool', 'dnsrecon')
            confirm.assert_not_called()

    def test_cli_runs_outside_checkout_without_gui(self):
        """The CLI locates release metadata outside the checkout and renders the configured banner."""
        for args in (['--help'], ['version'], ['run', 'invalid', 'invalid']):
            result = subprocess.run([sys.executable, str(ROOT / 'asadt.py'), *args],
                                    cwd=self.temp.name, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 3 if args[0] == 'run' else 0, result.stderr)
            if args == ['version']:
                config = TOML_Loader(str(ROOT / 'config')).loadfile('scriptinfo.toml')
                output = result.stdout.decode('utf-8')
                self.assertIn('PROTECT THE FUTURE', output)
                self.assertIn('[' + config.dictionary['script_data']['script_version'] + '] [MARK IV]', output)
                frame = [line for line in output.splitlines() if line.startswith(('  ╔', '  ║', '  ╚'))]
                self.assertEqual(len(frame), 5)
                self.assertEqual(len(set(map(len, frame))), 1)

    def test_run_lists_tools_and_opens_form_by_short_name(self):
        """The CLI lists tools without Qt and resolves a unique short name to its form."""
        import asadt
        from typer.testing import CliRunner
        cli = CliRunner()
        with patch('libasadt4.displayboxhandler.DisplayBoxHandler_Service') as gui:
            for names, expected in [([], ('scantool', 'hacktool')), (['hacktool'], ('msfpc',))]:
                result = cli.invoke(asadt.cli_host, ['run', *names])
                self.assertEqual(result.exit_code, 0, result.output)
                for name in expected:
                    self.assertIn(name, result.output)
            self.assertNotIn('nmap', result.output)
            gui.assert_not_called()
            result = cli.invoke(asadt.cli_host, ['run', 'nikto'])
            self.assertEqual(result.exit_code, 1)  # Mock form requests exit.
            self.assertIn('  [!] QUITING UPON USER REQUEST', result.output.splitlines())
            self.assertEqual(gui.return_value.DISPLAY_UI_MODEL.call_args.args[0], 'nikto')

    def test_run_target_reaches_every_tool_with_form_defaults(self):
        """Terminal dispatch builds each tool's expected native command from shared form defaults."""
        import asadt
        from typer.testing import CliRunner
        domain_file, resolver_file = self.massdns_inputs()
        output = Path(self.temp.name, 'reports')
        output.mkdir()
        with patch('asadt.privilege_reasons', return_value=[]), \
             patch('libasadt4.displayboxhandler.DisplayBoxHandler_Service') as gui, \
             patch('libasadt4.modules_main.RunCommand', return_value=0) as run:
            for name, module in asadt.MODULES.items():
                for tool in module.submodules:
                    with self.subTest(tool=tool):
                        target = str(domain_file) if tool == 'massdns' else 'localhost'
                        options = ['--target', target, '--output-dir', str(output)]
                        edits = {0: target, OUTPUT_KEYS[tool]: str(output)}
                        if tool == 'nmap':
                            options += ['--ports', '80,443']
                            edits[1] = '80,443'
                        if tool == 'massdns':
                            options += ['--resolvers', str(resolver_file)]
                            edits[1] = str(resolver_file)
                        config = TOML_Loader(ROOT / 'config').loadfile(f'{name}/{tool}.toml').dictionary
                        values = self.form(tool, config).collect_values()
                        values.update(edits)
                        expected = module(tool, config, values).build_command()
                        result = CliRunner().invoke(asadt.cli_host, ['run', tool, *options])
                        self.assertEqual(result.exit_code, 0, result.output)
                        self.assertEqual(run.call_args.args[0], expected)
            gui.assert_not_called()

    def test_terminal_nmap_script_expression(self):
        """The terminal passes a complete NSE expression as one argument following --script."""
        import asadt
        from typer.testing import CliRunner
        expression = 'default and safe'
        with patch('asadt.privilege_reasons', return_value=[]), \
             patch('libasadt4.modules_main.RunCommand', return_value=0) as run:
            result = CliRunner().invoke(asadt.cli_host, [
                'run', 'nmap', '--target', 'localhost', '--ports', '80', '--script', expression,
                '--output-dir', self.temp.name,
            ])
            self.assertEqual(result.exit_code, 0, result.output)
            argv = run.call_args.args[0]
            self.assertEqual(argv[argv.index('--script') + 1], expression)

    def test_nse_names_against_local_catalog(self):
        """NSE validation accepts local names, paths and categories and rejects invalid selectors before launch."""
        import asadt
        from typer.testing import CliRunner
        scripts = Path(self.temp.name, 'scripts')
        scripts.mkdir()
        (scripts / 'script.db').write_text('Entry { filename = "http-title.nse", categories = { "lab", "safe" } }')
        custom = scripts / 'local script.nse'
        custom.touch()
        with patch.dict(os.environ, NMAPDIR=self.temp.name), patch('asadt.privilege_reasons', return_value=[]), \
             patch('libasadt4.modules_main.RunCommand', return_value=0) as run:
            for selector in ('http-title', '+http-title.nse,lab', '(http-* OR lab) AND not intrusive', str(custom)):
                command = self.module('nmap', {2: selector}).build_command()
                self.assertEqual(command[command.index('--script') + 1], selector)
            output = Path(self.temp.name, 'not-created')
            for selector in ('http-titel', 'safe or http-titel', 'http-missing*', 'safe and (lab', 'safe,,lab'):
                with self.subTest(selector=selector):
                    result = CliRunner().invoke(asadt.cli_host, ['run', 'nmap', '--target', 'localhost',
                        '--ports', '80', '--script', selector, '--output-dir', str(output), '--debugger'])
                    self.assertEqual(result.exit_code, 3, result.output)
                    self.assertIn('Nmap --script:', result.output)
            self.assertFalse(output.exists())
            run.assert_not_called()
            module = self.module('nmap', {2: 'http-titel'}, verify=False)
            module.execute_properties['ScriptEnablers']['nmap_nsescriptscan_enable'] = False
            self.assertNotIn('--script', ScanTool('nmap', module.execute_properties, module.execute_arguments).build_command())

    def test_verified_network_fields(self):
        """Valid network fields build commands and malformed addresses or ports exit with status 3."""
        valid = [('nmap', {0: '192.0.2,3.1-9', 1: 'T:0,80,443,U:53,S:1-9,P:255'}),
                 ('nmap', {0: '2001:db8::1/64', 5: True, 1: '-'}),
                 ('nmap', {0: 'localhost/24', 1: '[-1024],http*'}),
                 ('nikto', {0: 'https://[2001:db8::1]:8443/admin', 1: '80,8000-8010'}),
                 ('msfpc', {0: 'eth0', 1: '65535'}),
                 ('dnsrecon', {2: '192.0.2.1,2001:db8::53'})]
        for tool, edits in valid:
            with self.subTest(tool=tool, edits=edits):
                self.assertTrue(self.module(tool, edits).build_command())
        invalid = [('nmap', {0: '999.0.0.1'}), ('nmap', {0: '192.0.2.1/33'}),
                   ('nmap', {0: '192.0.2.9-2'}), ('nmap', {1: 'T:80,U:65536'}),
                   ('nmap', {1: '80-70'}), ('nmap', {1: 'P:1,256'}),
                   ('nmap', {9: '2001:db8::g'}), ('nmap', {10: '1-2'}),
                   ('nikto', {1: '0'}), ('msfpc', {1: '65536'}), ('dnsrecon', {2: '1.2.3.4,1.2.3.256'}),
                   ('dmitry', {0: '1.2.3.4.5'}), ('dnsmap', {0: '1.2.3.256'}),
                   ('assetfinder', {0: 'bad..test'}), ('wpscan', {0: 'http://127.0.0.999/blog'}),
                   ('dirb', {0: 'http://localhost:65536'}), ('spiderfoot-cli', {0: 'http://[::1]:foo'})]
        for tool, edits in invalid:
            with self.subTest(tool=tool, edits=edits), self.assertRaises(SystemExit) as result:
                self.module(tool, edits)
            self.assertEqual(result.exception.code, 3)

    def test_unavailable_nse_catalog_explains_how_to_verify_names(self):
        """A missing NSE catalog produces a diagnostic identifying NMAPDIR for an unverifiable name."""
        with patch.object(ArgVerify, '_script_directories', return_value=[Path(self.temp.name)]):
            ArgVerify.verify_nse_selector('not intrusive')
            with self.assertRaisesRegex(ValueError, 'NMAPDIR'):
                ArgVerify.verify_nse_selector('http-title')

    def test_nmap_checks_hostname_resolution_before_launch(self):
        """Nmap resolves hostnames in the selected address family before preparing output."""
        import socket
        import asadt
        from typer.testing import CliRunner

        output = Path(self.temp.name, 'reports')
        with patch('asadt.privilege_reasons', return_value=[]), \
             patch('libasadt4.modules_main.socket.getaddrinfo', side_effect=socket.gaierror(-2, 'name unknown')) as lookup, \
             patch('libasadt4.modules_main.RunCommand') as run:
            result = CliRunner().invoke(asadt.cli_host, ['run', 'nmap', '--target', 'happy', '--ports', '80',
                                                          '--output-dir', str(output)])
            self.assertEqual(result.exit_code, 3, result.output)
            self.assertIn("Could not resolve 'happy'", result.output)
            lookup.assert_called_once_with('happy', None, socket.AF_INET, socket.SOCK_STREAM)
            run.assert_not_called()
            self.assertFalse(output.exists())

        address = (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::1', 0, 0, 0))
        with patch('libasadt4.modules_main.socket.getaddrinfo', return_value=[address]) as lookup:
            self.assertEqual(self.module('nmap', {0: 'happy/64', 5: True}).build_command()[-1], 'happy/64')
            self.module('nmap', {0: '192.0.2.1/24'})
            self.module('nmap', {0: '192.0.2.1-3'})
            lookup.assert_called_once_with('happy', None, socket.AF_INET6, socket.SOCK_STREAM)

    def test_no_argverify_applies_to_one_target_run(self):
        """Bypassing verification affects one terminal run and still requires output and overwrite checks."""
        import asadt
        import socket
        from typer.testing import CliRunner

        cli = CliRunner()
        output = Path(self.temp.name, 'reports')
        args = ['run', 'nmap', '--target', 'happy', '--ports', '80', '--output-dir', str(output)]
        with patch('asadt.privilege_reasons', return_value=[]), \
             patch('libasadt4.modules_main.RunCommand', return_value=0) as run:
            with patch('libasadt4.modules_main.ArgVerify') as verify:
                result = cli.invoke(asadt.cli_host, args + ['--no-argverify'], input='y\n')
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertTrue(output.is_dir())
                self.assertEqual(run.call_args.args[0][-1], 'happy')
                Path(output, 'nmap-fullscan_output.txt').touch()
                result = cli.invoke(asadt.cli_host, args + ['--no-argverify'], input='n\n')
                self.assertEqual(result.exit_code, 1, result.output)
                verify.assert_not_called()
            with patch('libasadt4.modules_main.socket.getaddrinfo', side_effect=socket.gaierror('unknown')):
                result = cli.invoke(asadt.cli_host, args)
                self.assertEqual(result.exit_code, 3, result.output)
                self.assertIn("Could not resolve 'happy'", result.output)
            run.assert_called_once()
        result = cli.invoke(asadt.cli_host, ['run', 'nmap', '--no-argverify'])
        self.assertEqual(result.exit_code, 3)
        self.assertIn('Supply --target', result.output)

    def test_invalid_network_fields_stop_terminal_run(self):
        """An invalid terminal network field stops execution before output creation and identifies the field."""
        import asadt
        from typer.testing import CliRunner
        output = Path(self.temp.name, 'new-report-directory')
        for tool, options, field in (
                ('nmap', ['--target', 'localhost', '--ports', '-1024,65536'], 'Port or Port Range'),
                ('msfpc', ['--target', 'eth0', '--ports', 'abc'], 'Connection Port'),
                ('nikto', ['--target', 'https://[::1]:70000'], 'Target Address')):
            with self.subTest(tool=tool), patch('asadt.privilege_reasons', return_value=[]), \
                 patch('libasadt4.modules_main.RunCommand') as run:
                result = CliRunner().invoke(asadt.cli_host, ['run', tool, *options, '--output-dir', str(output)])
                self.assertEqual(result.exit_code, 3, result.output)
                self.assertIn(field, result.output)
                self.assertFalse(output.exists())
                run.assert_not_called()

    def test_gui_can_correct_rejected_field_and_keep_other_values(self):
        """Correcting an NSE selector in the form preserves the target and ports."""
        rules = TOML_Loader(ROOT / 'config').loadfile('scantool/nmap.toml').dictionary
        dialog = ToolDialog('nmap', config=rules, runner_type=ScanTool)
        self.addCleanup(delete, dialog)
        dialog.fields[16].setCurrentText('TCP Connect Scan')
        output = Path(self.temp.name, 'reports')
        for key, value in ((0, 'localhost'), (1, '80,443'), (2, 'safe and ('), (15, str(output))):
            dialog.fields[key].setText(value)
        with patch.object(dialog, 'privilege_warning', return_value=''), \
             patch('libasadt4.displayboxhandler.QMessageBox.warning') as warning:
            dialog.request_execute()
            self.assertIn('Nmap --script', warning.call_args.args[2])
            self.assertEqual(dialog.navigation.currentItem().text(), 'Scan Tuning')
            self.assertEqual(dialog.fields[2].selectedText(), 'safe and (')
            self.assertIsNone(dialog.runner)
            self.assertFalse(output.exists())
            dialog.fields[2].setText('safe')
            from PySide6.QtWidgets import QMessageBox
            with patch.object(QMessageBox, 'question', return_value=QMessageBox.StandardButton.Yes):
                dialog.request_execute()
        self.assertEqual(dialog.action, 'execute')
        command = dialog.runner.build_command()
        self.assertEqual(command[command.index('--script') + 1], 'safe')
        self.assertEqual(command[command.index('-p') + 1], '80,443')
        self.assertEqual(command[-1], 'localhost')

    def test_interactive_terminal_repairs_or_cancels(self):
        """Interactive repair retains the target, runs with a corrected port and stops on refusal or EOF."""
        import asadt
        class Terminal(StringIO):
            """Present a scripted input buffer as an interactive terminal.

            Use `StringIO` responses to exercise the CLI's correction branch without an
            actual terminal.
            """
            def isatty(self):
                """Advertise the fixture stream as a TTY.

                Return true so the runner offers interactive field repair.
                """
                return True

        args = dict(module_name='nmap', target='localhost', ports='70000', output_dir=self.temp.name)
        with patch('asadt.privilege_reasons', return_value=[]), \
             patch('libasadt4.modules_main.RunCommand', return_value=0) as run:
            for answers in ('n\n', 'y\n', ''):
                with self.subTest(answers=answers), patch('sys.stdin', Terminal(answers)), self.assertRaises(SystemExit) as result:
                    asadt.asadtexec(**args)
                self.assertEqual(result.exception.code, 3)
                run.assert_not_called()
            with patch('sys.stdin', Terminal('y\n70001\ny\n443\n')), self.assertRaises(SystemExit) as result:
                asadt.asadtexec(**args)
            self.assertEqual(result.exception.code, 0)
            run.assert_called_once()
            command = run.call_args.args[0]
            self.assertEqual(command[command.index('-p') + 1], '443')
            self.assertEqual(command[-1], 'localhost')

    def test_run_terminal_validation_overwrite_and_exit_status(self):
        """Terminal validation and overwrite decisions protect existing reports and propagate child status."""
        import asadt
        from typer.testing import CliRunner
        cli = CliRunner()
        with patch('libasadt4.modules_main.RunCommand', return_value=17) as run:
            for args, hint in [
                (['nmap', '--target', 'localhost'], '--ports'),
                (['massdns', '--target', 'domains.txt'], '--resolvers'),
                (['nikto', '--port', '80'], '--target'),
                (['nmap', '--script', 'http-title'], '--target'),
                (['nikto', '--target', 'localhost', '--script', 'http-title'], 'does not apply'),
                (['dnsrecon', '--target', 'localhost', '--ports', '80'], 'does not apply'),
                (['scantool', 'msfpc'], 'Unknown scantool tool'),
            ]:
                result = cli.invoke(asadt.cli_host, ['run', *args])
                self.assertEqual(result.exit_code, 3, result.output)
                self.assertIn(hint, result.output)
            report = Path(self.temp.name, 'assetfinder.txt')
            report.write_text('previous report')
            args = ['run', 'scantool', 'assetfinder', '--target', 'example.test', '--output-dir', self.temp.name]
            result = cli.invoke(asadt.cli_host, args, input='n\n')
            self.assertEqual(result.exit_code, 1, result.output)
            warning = ('  [!] OVERWRITE WARNING\n'
                       '      Would you like to overwrite the following existing report files?\n'
                       f'      {report} y/n')
            self.assertIn(warning + ' ', result.output)
            result = cli.invoke(asadt.cli_host, args, input='\n', color=True)
            self.assertEqual(result.exit_code, 1, result.output)
            self.assertIn(asadt.TypeCLI.style(warning, fg='yellow', bold=True), result.output)
            run.assert_not_called()
            self.assertEqual(report.read_text(), 'previous report')
            result = cli.invoke(asadt.cli_host, args, input='y\n')
            self.assertEqual(result.exit_code, 17, result.output)
            self.assertIn(warning + ' y\n\n', result.output)
            self.assertEqual(run.call_args.kwargs['stdout_path'], str(report))

    def test_terminal_run_stops_when_confirmation_is_unavailable(self):
        """EOF at a directory or privilege prompt cancels the run before tool execution."""
        import asadt
        from typer.testing import CliRunner
        cli = CliRunner()
        directory = Path(self.temp.name, 'new')
        with patch('libasadt4.modules_main.RunCommand') as run:
            result = cli.invoke(asadt.cli_host, ['run', 'assetfinder', '--target', 'example.test',
                                                 '--output-dir', str(directory)])
            self.assertEqual(result.exit_code, 3, result.output)
            self.assertFalse(directory.exists())
            with patch('asadt.privilege_reasons', return_value=['Raw packets require privileges.']):
                result = cli.invoke(asadt.cli_host, ['run', 'nmap', '--target', 'localhost', '--ports', '80'])
                self.assertEqual(result.exit_code, 1, result.output)
                self.assertIn('Execute with current permissions?', result.output)
            run.assert_not_called()


    def test_nmap_and_nikto_report_paths_are_validated_before_launch(self):
        from libasadt4.output_paths import report_path
        from libasadt4.tool_config import initial_values

        for tool, key in [('nmap', 'nmap_fullscan_output_filename'), ('nikto', 'nikto_default_output_filename')]:
            config = TOML_Loader(ROOT / 'config').loadfile(f'scantool/{tool}.toml').dictionary
            values = initial_values(tool, config)
            values[OUTPUT_KEYS[tool]] = self.temp.name
            names = ['../sibling.txt', '/tmp/sibling.txt', r'C:\reports\sibling.txt', r'..\sibling.txt']
            if tool == 'nmap':
                names.extend(['report-%Y.txt', 'report-%%.txt'])
            for name in names:
                with self.subTest(tool=tool, name=name):
                    config['ScriptOutput'][key] = name
                    with self.assertRaisesRegex(ValueError, key):
                        validate_tool_config(tool, config)
                    with self.assertRaisesRegex(ValueError, key):
                        report_path(tool, values, config)
            config['ScriptOutput'][key] = 'report with spaces.txt'
            validate_tool_config(tool, config)
            self.assertEqual(Path(report_path(tool, values, config)), Path(self.temp.name, 'report with spaces.txt'))

    def test_nmap_rejects_percent_directories_before_creation(self):
        from libasadt4.output_paths import prepare_tool_output
        from libasadt4.tool_config import initial_values

        config = TOML_Loader(ROOT / 'config').loadfile('scantool/nmap.toml').dictionary
        config['ScriptOutput']['nmap_fullscan_output_format'] = 'oA'
        values = initial_values('nmap', config)
        destination = Path(self.temp.name, 'reports-%Y')
        values[OUTPUT_KEYS['nmap']] = str(destination)
        with self.assertRaisesRegex(ValueError, 'directory without %'):
            prepare_tool_output('nmap', values, config, lambda _: self.fail('unexpected creation prompt'))
        self.assertFalse(destination.exists())

    def test_report_symlink_cannot_overwrite_a_sibling(self):
        from libasadt4.output_paths import prepare_tool_output
        from libasadt4.tool_config import initial_values

        directory = Path(self.temp.name, 'reports')
        directory.mkdir()
        sibling = directory.parent / 'other.txt'
        sibling.write_text('previous')
        config = TOML_Loader(ROOT / 'config').loadfile('scantool/nmap.toml').dictionary
        config['ScriptOutput'].update(nmap_fullscan_output_format='oA', nmap_fullscan_output_filename='scan')
        try:
            (directory / 'scan.xml').symlink_to(sibling)
        except OSError as error:
            self.skipTest(f'Symlinks unavailable: {error}')
        values = initial_values('nmap', config)
        values[OUTPUT_KEYS['nmap']] = str(directory)
        with self.assertRaisesRegex(PermissionError, 'outside the output directory'):
            prepare_tool_output('nmap', values, config, lambda _: True)
        self.assertEqual(sibling.read_text(), 'previous')

    def test_update_preserves_working_directory_metadata(self):
        import asadt
        from typer.testing import CliRunner

        cli = CliRunner()
        self.addCleanup(os.chdir, Path.cwd())
        os.chdir(self.temp.name)
        with patch('libasadt4.mainprog.requests.get') as get:
            sentinel = Path('.newversion_scriptinfo.toml')
            sentinel.write_bytes(b'existing file')
            metadata = (ROOT / 'config/scriptinfo.toml').read_bytes()
            for body, status in [(metadata, 0), (b'[malformed', 3)]:
                get.return_value.content = body
                result = cli.invoke(asadt.cli_host, ['update'])
                self.assertEqual(result.exit_code, status, result.output)
                self.assertEqual(list(Path.cwd().iterdir()), [sentinel.absolute()])
                self.assertEqual(sentinel.read_bytes(), b'existing file')

            first = ProgUpdate('v4.0.1', 'https://example.test/scriptinfo.toml')
            second = ProgUpdate('v4.0.1', 'https://example.test/scriptinfo.toml')
            try:
                get.return_value.iter_content.return_value = [metadata]
                first.write_uf()
                second.write_uf()
                self.assertNotEqual(first.newversion_config, second.newversion_config)
                first.remove_uf()
                self.assertEqual(Path(second.newversion_config).read_bytes(), metadata)
            finally:
                first.remove_uf()
                second.remove_uf()
            self.assertEqual(sentinel.read_bytes(), b'existing file')


if __name__ == '__main__':
    unittest.main()
