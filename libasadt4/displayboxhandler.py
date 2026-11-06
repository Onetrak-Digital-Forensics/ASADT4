"""Collect tool arguments and per-run configuration in a modal Qt dialog.

DisplayBoxHandler_Service owns or reuses the QApplication. Each call to
DISPLAY_UI_MODEL opens a fresh ToolDialog and waits for it to close. The
dialog edits fields, checks the submission and can prepare a runner. asadtexec
starts that runner after control returns to the terminal.

For a new form option, start with the descriptor in gui_models.TOOL_MODELS.
ToolDialog.add_field renders it, collect_values serializes it under the same
integer key, and ArgVerify and the command builder interpret that key. For a
TOML setting that controls execution or report naming, see add_runtime_settings
instead. Those controls edit a per-dialog config dictionary.
"""

import os
from copy import deepcopy
from functools import partial
from pathlib import Path
from textwrap import fill
from libasadt4.modules_main import VerificationFailed
from libasadt4.privileges import privilege_message, privilege_reasons
from libasadt4.output_paths import check_tool_output, overwrite_question, prepare_tool_output, report_files
from libasadt4.tool_config import (
    ArgumentIssue, BOOLEAN_SETTINGS, OUTPUT_PREFIX, configured_report_filename, enabled, missing_required_fields, output_formats, validate_field,
    validate_tool_config, initial_values,
)

from PySide6.QtCore import Qt, qVersion
from PySide6.QtGui import QColor, QIcon, QPalette
from PySide6.QtWidgets import (
    QApplication, QButtonGroup, QCheckBox, QComboBox, QDialog,
    QFileDialog, QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QListWidget, QMessageBox, QPushButton, QRadioButton, QScrollArea,
    QSlider, QSpinBox, QStackedWidget, QVBoxLayout, QWidget,
)

from libasadt4.gui_models import (
    DNS_THREADED_MODES, OUTPUT_KEYS, RADIO_DEFAULTS, RECON_FIELDS, REQUIRED_KEYS, TOOL_MODELS, TOOL_NAMES,
)


def set_hover_help(widget, message):
    """Keep long examples together and give readers time to read the tip."""
    widget.setToolTip('\n'.join(fill(line, width=72, break_long_words=False, break_on_hyphens=False)
                                for line in message.splitlines()))
    widget.setToolTipDuration(60000)
    widget.setAccessibleDescription(message)


class ToolDialog(QDialog):
    """Edit and validate one tool submission in a modal Qt dialog.

    fields maps integer TOOL_MODELS keys to their value widgets. groups maps each
    group_id to an exclusive QButtonGroup. Sections appear in model order. Each
    navigation row shares an index with its scrollable page, allowing show_field_error
    to reveal a rejected field. Each model requires an Output section and a directory
    text field at OUTPUT_KEYS[tool]. Configuration errors select the final Runtime
    config page.

    collect_values reads the field widgets. Runtime controls write directly to the
    dialog's private configuration copy. On Run, the optional runner_type receives both
    sets of values while errors can still be corrected in the form.

    The initial action is 'quit', which covers Cancel and window close. request_edit
    sets 'edit'. A successful request_execute sets 'execute' after validation and
    overwrite confirmation.
    """

    def __init__(ToolWindow, toolname: str, parent=None, config=None, acknowledged=(), debug=None, *, runner_type=None):
        """Build the form and connect model fields to their widgets.

        Use `toolname` to select sections, defaults, output controls and runtime
        settings. Copy `config`, retain acknowledged privilege warnings, and use
        optional `debug` and `runner_type` callbacks during submission.
        """

        super().__init__(parent)
        ToolWindow.debug = debug
        ToolWindow.runner_type = runner_type
        ToolWindow.runner = None
        ToolWindow.first_paint_pending = bool(debug)
        ToolWindow.toolname = toolname
        ToolWindow.config = deepcopy(config)
        ToolWindow.verify_arguments = QCheckBox('Verify Arguments (ArgVerify)')
        ToolWindow.verify_arguments.setChecked(True)
        set_hover_help(ToolWindow.verify_arguments, 'Check your entries before running the tool. Leave this on '
                       'for help finding mistakes. Clearing it skips the tool-specific checks. Required fields '
                       'and output locations are still checked.')
        ToolWindow.initial_values = initial_values(toolname, config)
        ToolWindow.acknowledged = acknowledged
        ToolWindow.fields = {}
        ToolWindow.groups = {}
        ToolWindow.action = 'quit'
        display_name = TOOL_NAMES[toolname]
        ToolWindow.setWindowTitle(f'ASADT4 | {display_name}')
        ToolWindow.resize(1040, 760)
        ToolWindow.setMinimumSize(700, 520)
        palette = QPalette()
        for role in QPalette.ColorRole:
            if role not in (QPalette.ColorRole.NoRole, QPalette.ColorRole.NColorRoles):
                palette.setColor(role, QColor('#FF0000'))
        for role in (QPalette.ColorRole.Window, QPalette.ColorRole.Base, QPalette.ColorRole.AlternateBase,
                     QPalette.ColorRole.Button, QPalette.ColorRole.ToolTipBase, QPalette.ColorRole.HighlightedText):
            palette.setColor(role, QColor('#000000'))
        ToolWindow.setPalette(palette)
        ToolWindow.setStyleSheet(ToolWindow.window_style())

        root = QVBoxLayout(ToolWindow)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(18)
        brand = QLabel('ASADT4  /  Assistive Search and Discovery Tool')
        brand.setObjectName('brand')
        root.addWidget(brand)
        title = QLabel(display_name)
        title.setObjectName('title')
        root.addWidget(title)
        subtitle = QLabel('Hover over a field for help.')
        subtitle.setObjectName('muted')
        root.addWidget(subtitle)

        body = QHBoxLayout()
        body.setSpacing(24)
        ToolWindow.navigation = QListWidget()
        ToolWindow.navigation.setFixedWidth(210)
        ToolWindow.pages = QStackedWidget()
        body.addWidget(ToolWindow.navigation)
        body.addWidget(ToolWindow.pages, 1)
        root.addLayout(body, 1)
        forms = {}
        if debug:
            debug(f'GUI TOOL_MODELS[{toolname!r}]: {len(TOOL_MODELS[toolname])} fields')
        for field in TOOL_MODELS[toolname]:
            section = field['section']
            if section not in forms:
                forms[section] = ToolWindow.add_section(section)
            ToolWindow.add_field(forms[section], field)
            if debug:
                debug(f"  [{field['key']}] {section} / {field['label']} ({field['kind']})")

        if toolname == 'msfpc':
            ToolWindow.groups['ss_type'].buttonToggled.connect(ToolWindow.refresh_msfpc_fields)
            ToolWindow.refresh_msfpc_fields()
        if toolname == 'dnsrecon':
            ToolWindow.fields[1].currentTextChanged.connect(ToolWindow.refresh_dns_threads)
            ToolWindow.refresh_dns_threads()

        ToolWindow.output_preview = QLabel()
        ToolWindow.output_preview.setWordWrap(True)
        ToolWindow.output_preview.setTextFormat(Qt.TextFormat.PlainText)
        forms['Output'].addRow(ToolWindow.output_preview)
        forms['Runtime Config'] = ToolWindow.add_section('Runtime Config')
        if config and 'ScriptEnablers' in config:
            ToolWindow.add_runtime_settings(forms['Runtime Config'])
        forms['Runtime Config'].addRow(ToolWindow.verify_arguments)
        ToolWindow.fields[OUTPUT_KEYS[toolname]].textChanged.connect(ToolWindow.refresh_output_preview)
        if toolname == 'dnsrecon':
            ToolWindow.fields[5].currentTextChanged.connect(ToolWindow.refresh_output_preview)
        ToolWindow.navigation.currentRowChanged.connect(ToolWindow.pages.setCurrentIndex)
        ToolWindow.navigation.currentTextChanged.connect(
            lambda section: ToolWindow.refresh_output_preview() if section == 'Output' else None)
        ToolWindow.refresh_output_preview()
        ToolWindow.navigation.setCurrentRow(0)
        footer = QHBoxLayout()
        output_hint = QLabel('See output in the terminal.')
        output_hint.setWordWrap(True)
        footer.addWidget(output_hint, 1)
        edit = QPushButton('Edit TOML in CnfEdit')
        edit.setToolTip('Close the form and open the saved TOML in nano or an available fallback editor.')
        edit.clicked.connect(ToolWindow.request_edit)
        quit_button = QPushButton('Cancel')
        quit_button.clicked.connect(ToolWindow.reject)
        ToolWindow.execute_button = QPushButton(f'Run {display_name}')
        ToolWindow.execute_button.setObjectName('primary')
        ToolWindow.execute_button.clicked.connect(ToolWindow.request_execute)
        for button in (edit, quit_button, ToolWindow.execute_button):
            button.setAutoDefault(False)
            footer.addWidget(button)
        root.addLayout(footer)
        if debug:
            debug(f'GUI built {toolname} form: {len(forms)} sections, {len(ToolWindow.fields)} fields')
            ToolWindow.verify_arguments.toggled.connect(
                lambda checked: debug(f'GUI ArgVerify {"active" if checked else "disabled"} for this run'))
            ToolWindow.navigation.currentTextChanged.connect(lambda section: debug(f'GUI section: {section}'))

    def add_section(self, section):
        """Create a scrollable section and its navigation entry.

        Append the page to the stacked widget and return its `QFormLayout` for the
        caller to populate.
        """
        self.navigation.addItem(section)
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 8, 16, 12)
        heading = QLabel(section)
        heading.setObjectName('heading')
        layout.addWidget(heading)
        form = QFormLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(12)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        layout.addLayout(form)
        layout.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(page)
        self.pages.addWidget(scroll)
        return form

    def add_runtime_settings(self, form):
        """Bind the per-run configuration controls to the dialog's TOML copy.

        Build enablers and tool-specific report or profile controls in `form`. Connect
        filename and format changes to the output preview.
        """
        form.addRow(QLabel(f'Settings from {self.toolname}.toml apply to this run only.'))
        rules = self.config['ScriptEnablers']
        switch_help = {
            self.toolname + '_enable': f'Allow {TOOL_NAMES[self.toolname]} to run with these settings.',
            'nmap_updatensedb': 'Rebuild the local list of Nmap scripts before scanning. Use this after adding '
                                'scripts. Your account needs permission to write the list.',
            'nmap_nsedebug_enable': 'Show the requests and replies from the selected scripts in the terminal. '
                                    'Requires script scanning and a script selection.',
            'nmap_nsescriptscan_enable': 'Allow extra checks written for Nmap. Choose the scripts and optional '
                                         'settings file under Scan Tuning. Clear to skip those checks.',
            'nmap_assumesudoperms_enable': 'Tell Nmap it can send packets that require elevated permissions. '
                                           'Choose this only if your account already has those permissions. '
                                           'Clear for an unprivileged scan.',
            'nikto_nointeractive': 'Run Nikto without asking for keyboard input. Clear to allow terminal prompts.',
            'msfpc_verboseout': 'Show extra details in the terminal while generating files in any output mode.',
        }
        for key, label in BOOLEAN_SETTINGS[self.toolname].items():
            widget = QCheckBox(label)
            widget.setObjectName(key)
            widget.setChecked(enabled(rules[key]))
            set_hover_help(widget, switch_help[key])
            widget.toggled.connect(partial(rules.__setitem__, key))
            form.addRow(widget)

        if self.toolname == 'nikto':
            profile = self.add_config_input(form, rules, 'nikto_cli_profile', 'Nikto CLI Profile',
                                            'Choose current if nikto -Help lists -nocookies, or legacy if it '
                                            'lists -usecookies. This matches the cookie switch and available '
                                            'report formats to your installed version.', ('legacy', 'current'))
            self.add_config_input(form, rules, 'nikto_displaytype', 'Display Codes (1–4, D, E, P, S, V)',
                                  'Choose what appears in the terminal. Enter at least one code. Join codes '
                                  'without spaces, as in EP for errors and progress.\n'
                                  '1 redirects, 2 cookies, 3 successful replies, 4 pages requiring login.\n'
                                  'D debugging details, E errors, P progress, S hides addresses and hostnames, '
                                  'V extra detail.')
        filename_help = 'Enter a filename for the report. Choose its folder on the Output page.'
        if self.toolname == 'dnsrecon' or self.toolname in RECON_FIELDS:
            output = self.config.setdefault('ScriptOutput', {})
            key = self.toolname + '_default_output_filename'
            output.setdefault(key, configured_report_filename(self.toolname, self.config))
            if self.toolname == 'dnsrecon':
                detail = 'Use a name such as inventory. The format on the Output page sets the extension.'
            else:
                example = 'inventory.json' if self.toolname == 'wpscan' else 'inventory.txt'
                detail = f'Use a name without a folder path, such as {example}.'
            filename = self.add_config_input(form, output, key, 'Report Filename', f'{filename_help} {detail}')
            filename.textChanged.connect(self.refresh_output_preview)
        if self.toolname in OUTPUT_PREFIX:
            output = self.config['ScriptOutput']
            prefix = OUTPUT_PREFIX[self.toolname]
            if self.toolname == 'nmap':
                format_help = ('Choose oN for a readable text report, oX for XML, oG for text you can search '
                               'by line, oS for stylized text, or oA to save text, XML and searchable reports together.')
                detail = ' For oA, enter a base name like inventory to get .nmap, .xml and .gnmap files.'
            else:
                format_help = ('Choose txt for plain text, csv for a spreadsheet, htm for a web browser, '
                               'json or xml for structured data, or sql for database statements.')
                detail = ''
            formats = self.add_config_input(form, output, prefix + 'format', 'Report Format', format_help,
                                            output_formats(self.toolname, rules))
            filename = self.add_config_input(form, output, prefix + 'filename', 'Report Filename',
                                             f'{filename_help} Match the name to the format, '
                                             f'for example inventory.xml for an XML report.{detail}')
            formats.currentTextChanged.connect(self.refresh_output_preview)
            filename.textChanged.connect(self.refresh_output_preview)
            if self.toolname == 'nikto':
                def refresh_formats():
                    """Synchronize Nikto report formats after a profile change.

                    The legacy profile supports nbe output. Switching to the
                    current profile removes that choice. A change in the
                    selected format updates the dialog's configuration copy.
                    """
                    choices = output_formats('nikto', rules)
                    if 'nbe' in choices and formats.findText('nbe') < 0:
                        formats.addItem('nbe')
                    elif 'nbe' not in choices:
                        formats.removeItem(formats.findText('nbe'))
                    help_text = format_help
                    if 'nbe' in choices:
                        help_text += ' Choose nbe for older Nessus-compatible software.'
                    set_hover_help(formats, help_text)
                    set_hover_help(form.labelForField(formats), help_text)
                profile.currentTextChanged.connect(refresh_formats)
                refresh_formats()

    @staticmethod
    def add_config_input(form, table, key, label, help_text, choices=()):
        """Add a control that writes directly to a runtime setting.

        Create a combo for `choices` or a line edit for text. Connect its change signal
        to `table[key]`, label it and return the widget.
        """
        if choices:
            widget = QComboBox()
            widget.addItems(choices)
            widget.setCurrentText(table.get(key, choices[0]))
            widget.currentTextChanged.connect(partial(table.__setitem__, key))
        else:
            widget = QLineEdit(table[key])
            widget.textChanged.connect(partial(table.__setitem__, key))
        widget.setObjectName(key)
        widget.setAccessibleName(label)
        form.addRow(label, widget)
        set_hover_help(widget, help_text)
        set_hover_help(form.labelForField(widget), help_text)
        return widget

    def paintEvent(ToolWindow, event):
        """Render the dialog and trace its first visible layout.

        Delegate `event` to Qt. When tracing is enabled, log the first section, window
        size and pixel ratio once.
        """
        super().paintEvent(event)
        if ToolWindow.first_paint_pending:
            ToolWindow.first_paint_pending = False
            section = ToolWindow.navigation.currentItem().text()
            ToolWindow.debug(f'GUI first paint: {section}, {ToolWindow.width()}x{ToolWindow.height()} '
                             f'(pixel ratio {ToolWindow.devicePixelRatioF():g})')

    def add_field(ToolWindow, form, field):
        """Create and register a Qt control for one model field.

        Use the field key for lookup, apply defaults and tooltips, and wire the
        appropriate radio group, file picker or paired slider. The registered control
        supplies the submitted value.

        The form reads its starting value from initial_values[field['key']]. A browse
        button writes into its line edit. A horizontal slider mirrors a spin box in both
        directions. Register only the value-owning control in fields or the pair would
        produce two submission entries. Likewise a RADIO_DEFAULTS reset button belongs
        to the Qt group only. Selecting it yields False for every keyed radio in that
        group.

        To add a widget kind, pair its construction here with a reader in collect_values
        and a matching initial_values representation. Disabled controls are still
        collected, so enforce mode restrictions in the verifier and command builder as
        well as in the widget's enabled state.
        """

        kind = field['kind']
        default = ToolWindow.initial_values[field['key']]
        label = field['label'].strip()
        required = field['key'] in REQUIRED_KEYS[ToolWindow.toolname]
        help_text = field['help']
        if kind == 'Input':
            help_text = ('Required. ' if required else 'Optional. ') + help_text
        elif kind == 'Slider':
            low, high = field['range']
            help_text += f'\nEnter a whole number from {low} to {high}. Starting value for this run is {default}.'
        if required and not label.endswith('*'):
            label += '*'
        if kind == 'Input':
            widget = QLineEdit()
            widget.setText(default)
            widget.setPlaceholderText('Required' if required else 'Optional')
        elif kind == 'Slider':
            widget = QSpinBox()
            widget.setRange(*field['range'])
            widget.setValue(default)
            if not field.get('show_slider'):
                widget.setSpecialValueText('Tool Default')
        elif kind == 'Listbox':
            widget = QComboBox()
            labels = field.get('choice_labels', {})
            for choice in field['choices']:
                widget.addItem(labels.get(choice, choice), choice)
            widget.setCurrentIndex(widget.findData(default[0]))
        elif kind == 'Checkbox':
            widget = QCheckBox(label)
            widget.setChecked(default)
        else:
            widget = QRadioButton(label)
            group_id = field['group_id']
            if group_id not in ToolWindow.groups:
                group = QButtonGroup(ToolWindow)
                ToolWindow.groups[group_id] = group
                if group_id in RADIO_DEFAULTS:
                    normal = QRadioButton(RADIO_DEFAULTS[group_id])
                    normal_help = {
                        'ssl_type': 'Let Nikto detect whether the site uses an encrypted HTTPS connection.',
                        'ss_type': 'Generate one payload using the format, console and connection settings you select.',
                    }
                    set_hover_help(normal, normal_help[group_id])
                    group.addButton(normal)
                    normal.setChecked(True)
                    form.addRow(normal)
            ToolWindow.groups[group_id].addButton(widget)
            widget.setChecked(default)
        set_hover_help(widget, help_text)
        widget.setAccessibleName(label)
        ToolWindow.fields[field['key']] = widget
        if field.get('show_slider'):
            slider = QSlider(Qt.Orientation.Horizontal)
            slider.setRange(widget.minimum(), widget.maximum())
            slider.setValue(widget.value())
            slider.setAccessibleName(label)
            set_hover_help(slider, help_text)
            slider.valueChanged.connect(widget.setValue)
            widget.valueChanged.connect(slider.setValue)
            row = QHBoxLayout()
            row.addWidget(slider, 1)
            row.addWidget(widget)
            form.addRow(label, row)
            set_hover_help(form.labelForField(row), help_text)
        elif field.get('directory') or field.get('input_file'):
            row = QWidget()
            layout = QHBoxLayout(row)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(widget, 1)
            browse = QPushButton('Browse…')
            browse.setAutoDefault(False)
            set_hover_help(browse, help_text)
            if field.get('directory'):
                browse.clicked.connect(lambda checked=False, target=widget: ToolWindow.browse_directory(target))
            else:
                def browse_file():
                    """Replace the field's path when the user selects a file."""
                    filename, _ = QFileDialog.getOpenFileName(ToolWindow, label, widget.text())
                    if filename:
                        widget.setText(filename)
                browse.clicked.connect(browse_file)
            layout.addWidget(browse)
            form.addRow(label, row)
            set_hover_help(form.labelForField(row), help_text)
        elif kind in ('Radio', 'Checkbox'):
            form.addRow(widget)
        else:
            form.addRow(label, widget)
            set_hover_help(form.labelForField(widget), help_text)

    def refresh_msfpc_fields(ToolWindow):
        """Enable the radio groups used by the selected output mode.

        Loop disables single-payload groups. Batch retains the console choice. Disabling
        a group preserves its selections for a later switch back.
        """
        loop = ToolWindow.fields[25].isChecked()
        batch = ToolWindow.fields[26].isChecked()
        for group in ('serve_type', 'stage_type', 'net_type', 'syntax_type', 'con_type'):
            active = not loop and (not batch or group == 'con_type')
            for button in ToolWindow.groups[group].buttons():
                button.setEnabled(active)

    def refresh_dns_threads(ToolWindow):
        """Apply DNSRecon's mode restriction to the worker control.

        Enable field 7 only for a mode listed in `DNS_THREADED_MODES`. The command
        builder applies the corresponding restriction to argv.
        """
        ToolWindow.fields[7].setEnabled(ToolWindow.fields[1].currentData() in DNS_THREADED_MODES)

    def browse_directory(ToolWindow, target):
        """Select an output directory for a line edit.

        Pass the existing text as the picker's starting path and replace it only after
        the user selects a directory.
        """

        directory = QFileDialog.getExistingDirectory(ToolWindow, 'Select Output Directory', target.text())
        if directory:
            target.setText(directory)

    def collect_values(ToolWindow):
        """Read the widgets into a fresh submission dictionary.

        Use integer model keys. Return stripped text, integer spin values, single-item
        lists for combos and booleans for checkable controls.
        """

        values = {}
        for key, widget in ToolWindow.fields.items():
            if isinstance(widget, QLineEdit):
                values[key] = widget.text().strip()
            elif isinstance(widget, QSpinBox):
                values[key] = widget.value()
            elif isinstance(widget, QComboBox):
                values[key] = [widget.currentData()]
            else:
                values[key] = widget.isChecked()
        return values

    def trace_submission(self, values):
        """Trace the captured form values and editable runtime settings.

        Render designated sensitive values as `<redacted>`. Include the backing settings
        for visible configuration controls before argument normalization.
        """
        self.debug(f'GUI captured input for {self.toolname}:')
        for field in TOOL_MODELS[self.toolname]:
            key = field['key']
            value = '<redacted>' if field.get('sensitive_flag') and values[key] else repr(values[key])
            self.debug(f"  [{key}] {field['label'].strip()}: {value}")
        # These tables back the editable runtime controls. Defaults can contain
        # credentials and are already represented by the submitted fields.
        for table in ('ScriptEnablers', 'ScriptOutput'):
            for key, value in (self.config or {}).get(table, {}).items():
                if self.findChild(QWidget, key) is not None:
                    self.debug(f'  {table}.{key}: {value!r}')

    def refresh_output_preview(ToolWindow):
        """Describe prospective output files in the form.

        Resolve filenames from current widgets and config, inspect the selected
        directory, and display collisions, access errors or MSFPC's naming pattern
        without creating reports.

        Connect a control that changes a destination to this method. For example,
        DNSRecon's format combo changes the report suffix as soon as its selection
        changes. report_files supplies the same concrete paths used for overwrite
        checks. A preview can go stale while the form stays open, so request_execute
        checks again on Run.
        """

        values = ToolWindow.collect_values()
        selected = values[OUTPUT_KEYS[ToolWindow.toolname]]
        if not selected:
            ToolWindow.output_preview.setText('Choose an output directory to preview the files.')
            return
        directory = Path(selected).absolute()
        lines = []
        try:
            paths = report_files(ToolWindow.toolname, values, ToolWindow.config)
        except ValueError as error:
            ToolWindow.output_preview.setText(str(error))
            return
        try:
            if directory.is_dir():
                with os.scandir(directory) as entries:
                    empty = next(entries, None) is None
                lines.append('Directory is empty.' if empty else 'Directory already contains files or folders.')
                check_tool_output(ToolWindow.toolname, values, ToolWindow.config)
            elif directory.exists():
                raise OSError(f'Select a directory. This path is a file: {directory}')
            else:
                lines.append('Directory will be created if you confirm.')
        except OSError as error:
            lines.append(str(error))

        if ToolWindow.toolname == 'msfpc':
            lines.append('MSFPC filename pattern: type-shell-stage-direction-method-port.ext '
                         'and a matching handler ending in -ext.rc.')
        for path in paths:
            lines.append(f'{"Already exists" if os.path.lexists(path) else "Planned file"}: {path.absolute()}')
        ToolWindow.output_preview.setText('\n'.join(lines))

    def show_field_error(self, key, title, message):
        """Bring a rejected field into view for correction.

        Find the field's section by key, scroll to its widget, show the diagnostic and
        focus the control. Select existing text in line edits.
        """
        field = next(field for field in TOOL_MODELS[self.toolname] if field['key'] == key)
        page = self.navigation.findItems(field['section'], Qt.MatchFlag.MatchExactly)[0]
        self.navigation.setCurrentItem(page)
        widget = self.fields[key]
        scroll = self.pages.currentWidget()
        scroll.ensureWidgetVisible(widget)
        QMessageBox.warning(self, title, message)
        widget.setFocus()
        if isinstance(widget, QLineEdit):
            widget.selectAll()

    def request_execute(ToolWindow):
        """Prepare the submission and accept the dialog after overwrite confirmation.

        Validate the edited TOML, required fields and setting-backed text inputs. Check
        privilege requirements introduced by the current selections. With verification
        enabled, the requested runner prepares the output directory using the dialog's
        confirm_create callback. When verification is disabled or runner_type is
        omitted, the form prepares the directory itself.

        A keyed ArgumentIssue, including one carried by VerificationFailed, selects the
        affected widget for correction. A declined prompt leaves the form open.
        Directory creation may already have occurred when the user declines an
        overwrite.

        On success, store the prepared runner, set action to 'execute' and accept the
        dialog. A caller that omits runner_type receives the submitted values with
        runner set to None.
        """

        values = ToolWindow.collect_values()
        if ToolWindow.debug:
            ToolWindow.trace_submission(values)
        if ToolWindow.config and 'ScriptEnablers' in ToolWindow.config:
            try:
                validate_tool_config(ToolWindow.toolname, ToolWindow.config)
            except ValueError as error:
                ToolWindow.navigation.setCurrentRow(ToolWindow.navigation.count() - 1)
                QMessageBox.warning(ToolWindow, 'Runtime Config', str(error))
                return
        missing = missing_required_fields(ToolWindow.toolname, values)
        if missing:
            labels = ', '.join(field['label'].strip().rstrip('*') for field in missing)
            ToolWindow.show_field_error(missing[0]['key'], 'Required Fields', 'Please complete: ' + labels)
            return
        for field in TOOL_MODELS[ToolWindow.toolname]:
            if field['kind'] == 'Input' and 'setting' in field:
                try:
                    validate_field(field, values[field['key']])
                except ValueError as error:
                    ToolWindow.show_field_error(field['key'], field['label'], str(error))
                    return
        warning = ToolWindow.privilege_warning(values)
        if warning:
            answer = QMessageBox.warning(
                ToolWindow, 'Nmap Privileges', warning + '\n\nContinue with current permissions?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if answer != QMessageBox.StandardButton.Yes:
                return
        def confirm_create(directory):
            """Ask whether the form may create a missing directory.

            Return true only for an explicit Yes. The output helper creates the
            directory after this callback returns.
            """
            answer = QMessageBox.question(
                ToolWindow, 'Create Output Directory', f'Create this output directory?\n{directory}',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            return answer == QMessageBox.StandardButton.Yes

        try:
            verify = ToolWindow.verify_arguments.isChecked()
            if ToolWindow.runner_type is None or not verify:
                if not prepare_tool_output(ToolWindow.toolname, values, ToolWindow.config, confirm_create):
                    return
            runner = None
            if ToolWindow.runner_type:
                runner = ToolWindow.runner_type(ToolWindow.toolname, ToolWindow.config, values,
                                                bool(ToolWindow.debug), ioverify=verify, confirm_create=confirm_create)
            if not ToolWindow.confirm_overwrite(values):
                return
        except VerificationFailed as failure:
            if isinstance(failure.issue, ArgumentIssue):
                ToolWindow.show_field_error(failure.issue.key, 'Check Argument', str(failure.issue))
            elif failure.issue is not None:
                QMessageBox.warning(ToolWindow, 'Check Arguments', str(failure.issue))
            return
        except ArgumentIssue as issue:
            ToolWindow.show_field_error(issue.key, 'Check Argument', str(issue))
            return
        except OSError as error:
            QMessageBox.warning(ToolWindow, 'Output Directory', str(error))
            return
        ToolWindow.runner = runner
        ToolWindow.action = 'execute'
        ToolWindow.accept()

    def confirm_overwrite(self, values):
        """Recheck collisions when the user submits the form.

        Return true when no question is needed or the user approves the current
        overwrite list. The confirmation defaults to No.
        """
        message = overwrite_question(self.toolname, values, self.config)
        if not message:
            return True
        answer = QMessageBox.question(self, 'Confirm Overwrite', message,
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                      QMessageBox.StandardButton.No)
        return answer == QMessageBox.StandardButton.Yes

    def privilege_warning(ToolWindow, values):
        """Describe privilege requirements added by the current form settings.

        Filter the reasons against those acknowledged before opening the form. Return an
        empty string if no additional warning applies.
        """

        reasons = privilege_reasons(ToolWindow.toolname, ToolWindow.config, values)
        pending = [reason for reason in reasons if reason not in ToolWindow.acknowledged]
        return privilege_message(pending) if pending else ''

    def request_edit(ToolWindow):
        """Hand off the saved TOML file to the terminal editor.

        Set the action to `edit` and accept the dialog. The CLI opens the file after the
        modal event loop returns.
        """

        ToolWindow.action = 'edit'
        ToolWindow.accept()

    @staticmethod
    def window_style():
        """Return the Qt stylesheet for the tool form.

        Supply a QSS string shared by the dialog's fields, navigation, buttons and
        scroll controls, using the red and black palette.
        """

        return """
            QWidget { background: #000000; color: #FF0000; font-size: 13px; }
            QLabel#brand { color: #FF0000; font-size: 11px; font-weight: 700; }
            QLabel#title { font-size: 34px; font-weight: 700; }
            QLabel#heading { font-size: 21px; font-weight: 600; padding-bottom: 18px; }
            QLabel#muted { color: #FF0000; }
            QListWidget { background: #000000; border: 1px solid #FF0000; border-radius: 10px; padding: 8px; outline: none; }
            QListWidget::item { padding: 14px 10px; border-radius: 6px; }
            QListWidget::item:selected { background: #FF0000; color: #000000; }
            QLineEdit, QSpinBox, QComboBox { background: #000000; border: 1px solid #FF0000; border-radius: 6px; padding: 6px 9px; min-width: 110px; selection-background-color: #FF0000; selection-color: #000000; }
            QLineEdit { placeholder-text-color: #FF0000; }
            QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border-color: #FF0000; }
            QSlider::groove:horizontal { height: 4px; background: #000000; border: 1px solid #FF0000; border-radius: 2px; }
            QSlider::sub-page:horizontal { background: #FF0000; }
            QSlider::handle:horizontal { width: 14px; margin: -5px 0; background: #FF0000; border: 1px solid #FF0000; border-radius: 7px; }
            QSlider::handle:horizontal:focus { background: #000000; }
            QPushButton { background: #000000; border: 1px solid #FF0000; border-radius: 6px; padding: 10px 16px; }
            QPushButton:hover { background: #FF0000; color: #000000; }
            QPushButton#primary { background: #FF0000; border-color: #FF0000; color: #000000; font-weight: 600; }
            QPushButton#primary:hover { background: #000000; color: #FF0000; }
            QCheckBox, QRadioButton { spacing: 10px; padding: 5px 0; }
            QCheckBox::indicator, QRadioButton::indicator { width: 16px; height: 16px; border: 1px solid #FF0000; background: #000000; }
            QRadioButton::indicator { border-radius: 8px; }
            QRadioButton:disabled, QSpinBox:disabled { color: #925959; }
            QCheckBox::indicator:checked, QRadioButton::indicator:checked { background: #FF0000; }
            QScrollBar { background: #000000; }
            QScrollBar::handle { background: #FF0000; min-height: 20px; }
            QToolTip { color: #FF0000; background: #000000; border: 1px solid #FF0000; padding: 8px; }
        """


class DisplayBoxHandler_Service:
    """Manage the Qt application and expose the result of each modal tool dialog.

    DISPLAY_UI_MODEL returns this service. Read event before using the other result
    attributes. Its values are 'quit', 'edit' and 'execute'. ui_request_exit and
    ui_request_editcnf expose the first two outcomes to existing callers. Each
    invocation replaces the previous result, including values and config on
    cancellation.

    values holds the final widget values, config the per-run TOML settings and ioverify
    the verification checkbox state. For an accepted submission with runner_type,
    runner.execute_arguments contains the prepared values, including defaults applied
    during verification. The caller starts execution with runner.cmdgen(). With
    runner_type omitted, runner is None.
    """

    uimodel_parameter_launchlist = list(TOOL_MODELS)

    def __init__(DisplayBoxHandler, debug=None):
        """Initialize the shared Qt application and the service result fields.

        Reuse an existing application if available. Select Qt dialogs on Wayland, use
        the available Adwaita theme when appropriate, and report platform details
        through the optional debug callback.
        """

        DisplayBoxHandler.debug = debug
        if debug:
            debug(f'GUI initializing Qt {qVersion()}')
        DisplayBoxHandler.application = QApplication.instance() or QApplication([])
        platform = DisplayBoxHandler.application.platformName()
        if platform.startswith('wayland'):
            # Keep file pickers and confirmations inside Qt on Wayland compositors
            # that cannot export a parent window handle to a native GTK dialog.
            QApplication.setAttribute(Qt.ApplicationAttribute.AA_DontUseNativeDialogs)
        if debug:
            debug(f'GUI platform: {platform}')
        if QIcon.themeName() == 'hicolor' and any(
            (Path(root) / 'Adwaita' / 'index.theme').is_file() for root in QIcon.themeSearchPaths()
        ):
            QIcon.setThemeName('Adwaita')
        DisplayBoxHandler.values = {}
        DisplayBoxHandler.ui_request_editcnf = False
        DisplayBoxHandler.ui_request_exit = False

    def DISPLAY_UI_MODEL(DisplayBoxHandler, displayboxid: str, config=None, acknowledged=(), *, runner_type=None):
        """Run a tool dialog and copy its result onto this service.

        Reject an unknown ID with `ValueError`. After the modal loop, record field
        values, config, runner, verification state and action flags, schedule deletion
        of the dialog, and return the service.
        """

        if displayboxid not in DisplayBoxHandler.uimodel_parameter_launchlist:
            raise ValueError(f'Unknown tool: {displayboxid}')
        dialog = ToolDialog(displayboxid, config=config, acknowledged=acknowledged, debug=DisplayBoxHandler.debug,
                            runner_type=runner_type)
        dialog.exec()
        if DisplayBoxHandler.debug:
            DisplayBoxHandler.debug(f'GUI closed: {dialog.action}')
        DisplayBoxHandler.values = dialog.collect_values()
        DisplayBoxHandler.runner = dialog.runner
        DisplayBoxHandler.config = dialog.config
        DisplayBoxHandler.ioverify = dialog.verify_arguments.isChecked()
        DisplayBoxHandler.ui_request_editcnf = dialog.action == 'edit'
        DisplayBoxHandler.ui_request_exit = dialog.action == 'quit'
        DisplayBoxHandler.event = dialog.action
        dialog.deleteLater()
        return DisplayBoxHandler
