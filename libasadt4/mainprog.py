"""Load project TOML, open configuration files, and manage CLI updates and banners."""

try:

    try:
        import tomllib as configloader
    except ModuleNotFoundError:
        import tomli as configloader
    import subprocess
    import os
    from pathlib import Path
    from tempfile import NamedTemporaryFile, TemporaryDirectory
    import requests
    from libasadt4.output_paths import check_writable
    from libasadt4.tool_config import validate_packages

    from rich import print
    from rich.markup import escape
    from rich.panel import Panel

except ImportError as ErrorID:

    print(f'Python Submodule Import Error: Failed To Import "mainprog" Module!\nREASON > {ErrorID}')
    raise SystemExit(3)


class TOML_Loader:
    """Read TOML from a file or binary stream and retain the result.

    loadfile and parceldecode return the loader. On success, status_ok is True and
    dictionary contains the parsed tables. On failure, status_ok is False, dictionary is
    None and status_data holds the exception. Each read replaces the previous result.
    """

    def __init__(TOML_PARSER, configuration_directory: str):
        """Select the base directory for file-backed TOML reads.

        Store `configuration_directory` for subsequent calls to `loadfile`. Parsing
        begins when a file or stream is supplied.
        """

        TOML_PARSER.parser_cnfdir = configuration_directory

    def loadfile(TOML_PARSER, file_id: str):
        """Load a binary TOML file relative to the configured base directory.

        Record the filename, parsed dictionary and status on this loader. File and parse
        failures are recorded in `status_data`. Return the loader on either path.
        """

        TOML_PARSER.parser_cnffileid = file_id

        try:

            with open(f'{TOML_PARSER.parser_cnfdir}/{file_id}', mode='rb') as filetoparse:

                TOML_PARSER.dictionary = configloader.load(filetoparse)
                TOML_PARSER.status_ok = True
                TOML_PARSER.status_data = 'OK'

                return TOML_PARSER

        except Exception as ErrorID:

            TOML_PARSER.dictionary = None
            TOML_PARSER.status_ok = False
            TOML_PARSER.status_data = ErrorID

            return TOML_PARSER
        
    def parceldecode(TOML_PARSER, binary_data):
        """Read TOML from a caller-supplied binary stream and return the loader.

        The loader takes ownership of the stream and closes it through its context
        manager. Inspect status_ok before reading dictionary.
        """

        TOML_PARSER.parser_cnffileid = binary_data

        try:

            with binary_data as datatoparse:

                TOML_PARSER.dictionary = configloader.load(datatoparse)
                TOML_PARSER.status_ok = True
                TOML_PARSER.status_data = 'OK'

                return TOML_PARSER

        except Exception as ErrorID:

            TOML_PARSER.dictionary = None
            TOML_PARSER.status_ok = False
            TOML_PARSER.status_data = ErrorID

            return TOML_PARSER

class CnfEdit:
    """Launch a terminal editor for persistent configuration changes.

    The CLI and GUI use this launcher with a starting line and optional read-only mode.
    It delegates editing to an installed program and propagates the editor's exit
    status.
    """

    def __init__(self, start_line: int, editor_type: str = 'nano', user_fileperm: bool = False, read_only: bool = False):
        """Set editor preferences for later file opens.

        Retain the starting line, preferred editor, read-only flag and legacy
        permission-change opt-in. The default writable path preserves the original mode.
        """

        self.host_editor = editor_type
        self.start_ln = start_line
        self.change_fileperm_on_ctrlx = user_fileperm
        self.open_ro = read_only

    @staticmethod
    def display_banner():
        """Identify the configuration editor in the console.

        Print a Rich panel independently of TOML parsing so a user can still open and
        repair an invalid configuration.
        """
        print(Panel.fit('ASADT configuration editor', title='CnfEdit', border_style='bold red'))

    def run_editor(self, file_to_edit: str):
        """Open a configuration file and exit with the editor's status.

        Writable edits require write access. Try the preferred editor first, then the
        available fallbacks if an executable is missing. On Windows, writable edits also
        support Notepad. Launch or access errors exit with status 1. When explicitly
        requested, a successful writable edit sets the file mode to 0o751.
        """
        preferred = 'vim' if self.host_editor == 'vim' else 'nano'
        editors = list(dict.fromkeys([preferred, 'nano', 'vim', 'vi']))
        if os.name == 'nt' and not self.open_ro:
            editors.append('notepad')
        try:
            if not self.open_ro:
                check_writable(file_to_edit)
            for editor in editors:
                command = [editor]
                if editor == 'nano':
                    command.extend(['-l', '-L'])
                if self.open_ro:
                    command.append('-v' if editor == 'nano' else '-R')
                if editor != 'notepad':
                    command.append(f'+{self.start_ln}')
                command.append(file_to_edit)
                try:
                    status = subprocess.call(command)
                except FileNotFoundError:
                    print(f'{editor} was not found on PATH.')
                    continue
                if status == 0 and self.change_fileperm_on_ctrlx and not self.open_ro:
                    os.chmod(file_to_edit, 0o751)
                raise SystemExit(status)
        except OSError as error:
            print(escape(str(error)))
            raise SystemExit(1) from error
        print(f'Install a configuration editor on PATH. Tried {", ".join(editors)}.')
        raise SystemExit(1)

class ProgBanner:
    """Render the CLI's short or full Mark IV banner.

    Construct with the release identifier from local metadata. The full form includes
    the developer credit, while the short form can identify a debug session.
    """

    def __init__(ProgBanner, current_version: str):
        """Prepare the two Rich banner strings for this version.

        Embed `current_version` in the short banner and escape its centered release
        label in the full banner footer.
        """

        ProgBanner.cv_oncreate = current_version

        credit = 'Script Developed By 0DFS3C'
        release = f'[{current_version}] [MARK IV]'
        width = max(40, len(release))
        footer = '\n'.join((
            '  ╔' + '═' * width + '╗',
            f'  ║{credit:^{width}}║',
            '  ║' + escape(release.center(width)) + '║',
            f'  ║{"":{width}}║',
            '  ╚' + '═' * width + '╝',
        ))
        ProgBanner.type_normal = '''\n[red bold]             (                ( \n     (       )\\ )     (       )\\ )     *   ) \n     )\\     (()/(     )\\     (()/(     )  /( \n  ((((_)(    /(_)) ((((_)(    /(_))   ( )(_))  ⌠A⌡ssistive M\n   )\\ _ )\\  (_))    )\\ _ )\\  (_))_   (_(_())   ⌠S⌡earch    A\n   (_)_\\(_) / __|   (_)_\\(_)  |   \\  |_   _|   ⌠A⌡nd       R\n    / _ \\   \\__ \\    / _ \\    | |) |   | |     ⌠D⌡iscovery K\n   /_/ \\_\\  |___/   /_/ \\_\\   |___/    |_|     ⌠T⌡ool      4\n ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n ⌠PROTECT THE INNOCENT⌡ ⌠PROTECT THE INTERNET⌡\n             ⌠PROTECT THE FUTURE⌡\n''' + footer + '\n[/red bold]'
        ProgBanner.type_short = '''\n[red bold]   █████╗  ███████╗  █████╗  ██████╗  ████████╗\n  ██╔══██╗ ██╔════╝ ██╔══██╗ ██╔══██╗ ╚══██╔══╝\n  ███████║ ███████╗ ███████║ ██║  ██║    ██║\n  ██╔══██║ ╚════██║ ██╔══██║ ██║  ██║    ██║\n  ██║  ██║ ███████║ ██║  ██║ ██████╔╝    ██║\n  ╚═╝  ╚═╝ ╚══════╝ ╚═╝  ╚═╝ ╚═════╝     ╚═╝\n  Assistive Search And Discovery Tool ''' + ProgBanner.cv_oncreate + '\n\n  Happy Hacking ;P\n'

    def display_banner(ProgBanner, banner_type: str = 'normal', *, debugger: bool = False):
        """Print the requested banner variant.

        Use `normal` for the full artwork or `short` for the compact header. The
        optional debug marker applies to the short header.
        """

        if banner_type == 'normal':

            print(ProgBanner.type_normal)

        elif banner_type == 'short':

            banner = ProgBanner.type_short
            if debugger:
                banner += '[/red bold]  [bold purple][DEBUG SESSION ACTIVE][/bold purple]\n'
            print(banner)

class ProgUpdate:
    """Fetch release metadata and archives or install Linux dependencies.

    Construction requests the metadata URL with a timeout. Release operations use the
    working directory. The separate class-level APT entry point validates package names
    and checks privileges.
    """

    def __init__(ProgUpdate, current_hsv: str, update_target: str):
        """Fetch metadata for comparison with the locally configured version.

        The GET uses a 30-second timeout. Allocate private scratch space only
        when a caller requests a file-backed copy of the response.
        """

        ProgUpdate.current_host_script_version = current_hsv
        ProgUpdate.script_check_target = update_target
        ProgUpdate._metadata_dir = None
        ProgUpdate.newversion_config = None
        ProgUpdate.updatecap = requests.get(update_target, timeout=30)

    def write_uf(ProgUpdate):
        """Persist the fetched metadata for the local TOML loader.

        Keep the legacy relative-path interface, using a directory owned by this
        update instance so concurrent checks and existing files are independent.
        """

        if ProgUpdate._metadata_dir is None:
            ProgUpdate._metadata_dir = TemporaryDirectory(prefix='.newversion_', dir=Path.cwd())
        path = Path(ProgUpdate._metadata_dir.name) / 'scriptinfo.toml'
        ProgUpdate.newversion_config = os.path.relpath(path)
        ProgUpdate.save_download(path, ProgUpdate.updatecap)

    @staticmethod
    def save_download(filename, response):
        """Stream a response to a temporary file in the destination directory.

        Write in 512 KiB chunks and replace the destination after the response has been
        written. Remove the staging file on exit. Request exceptions propagate to the
        caller. A failure to open, write or replace the destination exits with status 1.
        """

        path = Path(filename).absolute()
        staging = None
        try:
            check_writable(path)
            with NamedTemporaryFile(dir=path.parent, delete=False) as output:
                staging = Path(output.name)
                for chunk in response.iter_content(chunk_size=512 * 1024):
                    output.write(chunk)
            os.replace(staging, path)
        except requests.RequestException:
            raise
        except OSError:
            print(escape(f'Cannot write to this path: {path}'))
            raise SystemExit(1)
        finally:
            if staging is not None:
                staging.unlink(missing_ok=True)

    def remove_uf(ProgUpdate):
        """Delete the downloaded metadata after parsing.

        Release only the scratch directory allocated by this update instance.
        """

        if ProgUpdate._metadata_dir is not None:
            ProgUpdate._metadata_dir.cleanup()
            ProgUpdate._metadata_dir = None
            ProgUpdate.newversion_config = None

    def check_rfs(ProgUpdate):
        """Check the metadata response before writing it.

        Call the response's `raise_for_status()` so an unsuccessful HTTP status
        propagates to the caller.
        """

        ProgUpdate.updatecap.raise_for_status()

    def verify_update_requirements(ProgUpdate, new_hsv: str):
        """Report whether the remote release identifier differs from the local one.

        Return the result of a case-sensitive string comparison. Any distinct identifier
        qualifies for the download prompt, including an older release.
        """

        current_version = ProgUpdate.current_host_script_version
        newvtosatisfy = new_hsv

        update_required = bool()

        if current_version == newvtosatisfy:

            update_required = False

            print('[green bold]  [!] ASADT4 Updater > No Update Was Reported From GitHub!\n\n')
        
        else:

            update_required = True

            print(f'[yellow bold]  [!] An Update For ASADT4 Is Available! ({current_version} --> {newvtosatisfy})\n[blue bold]  [?] Would You Like To Download The Release Package?\n[purple bold]  [?] LOC --> {os.getcwd()}')

        return update_required

    def new_release_download(ProgUpdate, release_url: str, release_id: str):
        """Download the selected ASADT4 release archive.

        Append `/<release_id>.zip` to the base URL, check the HTTP status, and save the
        response as `ASADT4_<release_id>.zip` in the current directory.
        """

        new_update_url = release_url + '/' + release_id + '.zip'

        print(new_update_url)

        releasecap = requests.get(new_update_url, timeout=30)

        releasecap.raise_for_status()

        ProgUpdate.save_download('ASADT4_' + release_id + '.zip', releasecap)

    def localdebupdate(toolbox_main=None, *, packages=None):
        """Install validated dependency packages on an elevated Linux host.

        Accept the configured package list or the legacy tool registry. Run `apt update`
        followed by `apt install -y` only on success. Propagate APT failure status and
        reject non-root execution.
        """

        # Preserve the registry argument accepted by older module callers.
        if toolbox_main is not None:
            packages = toolbox_main['scantool'].split() + toolbox_main['hacktool'].split()
            packages = ['spiderfoot' if name == 'spiderfoot-cli' else name for name in packages]
        validate_packages(packages)

        if not hasattr(os, 'geteuid'):
            print('[red bold]  [!] Run the APT dependency update on Kali or Parrot Linux.')
            raise SystemExit(1)
        if os.geteuid() != 0:
            print('[yellow bold]  [!] Updating APT dependencies requires root privileges. '
                  'From the checkout, run:[/yellow bold]\nsudo .venv/bin/python asadt.py update --apt-dep-update')
            raise SystemExit(1)

        print(f'[yellow bold]  Checking for APT package updates: {" ".join(packages)}')

        result = subprocess.call(['apt', 'update'])
        if result == 0:
            result = subprocess.call(['apt', 'install', '-y'] + packages)
        if result:
            raise SystemExit(result)
        return
