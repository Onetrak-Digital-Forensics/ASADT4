"""Describe the running script and flag Nmap options that need extra privileges."""

import os
import stat
from pathlib import Path

from libasadt4.gui_models import NMAP_SCAN_METHOD_LABELS
from libasadt4.tool_config import enabled, initial_values


def script_permissions(script):
    """Describe the script's filesystem access and the process's privilege level.

    Return a diagnostic string with the absolute path, mode and access flags when
    available. Use the effective UID on POSIX or the administrator check on Windows.
    """
    path = Path(script).absolute()
    try:
        mode = path.stat().st_mode
        access = ''.join(letter if os.access(path, flag) else '-'
                         for letter, flag in [('r', os.R_OK), ('w', os.W_OK), ('x', os.X_OK)])
        detail = f'mode={stat.filemode(mode)} ({stat.S_IMODE(mode):04o}), access={access}'
    except OSError as error:
        detail = f'file status unavailable ({error})'
    if hasattr(os, 'geteuid'):
        uid = os.geteuid()
        process = f'effective UID={uid} ({"root" if uid == 0 else "non-root"})'
    elif os.name == 'nt':
        import ctypes
        process = 'Windows administrator' if ctypes.windll.shell32.IsUserAnAdmin() else 'Windows standard user'
    else:
        process = 'process privilege level unavailable'
    return f'Script permissions: {path}, {detail}, {process}'


def privilege_reasons(tool, config, values=None):
    """Return the privilege warnings for a non-root POSIX Nmap run.

    Inspect access to the NSE database when an update is requested, the privileged
    discovery setting, selected scan method and raw-packet options such as traceroute
    and OS detection. Use the configured defaults until values are supplied. Other tools,
    disabled Nmap configurations and privileged processes receive an empty list.
    """
    if tool != 'nmap' or not hasattr(os, 'geteuid') or os.geteuid() == 0:
        return []
    rules = (config or {}).get('ScriptEnablers', {})
    if not enabled(rules.get('nmap_enable', True)):
        return []
    reasons = []
    if enabled(rules.get('nmap_updatensedb', False)):
        roots = [Path.home() / '.nmap', Path('/usr/local/share/nmap'), Path('/usr/share/nmap')]
        if os.environ.get('NMAPDIR'):
            roots.insert(0, Path(os.environ['NMAPDIR']))
        scripts = next((root / 'scripts' for root in roots if (root / 'scripts').is_dir()), None)
        if scripts:
            database = scripts / 'script.db'
            if not os.access(database if database.exists() else scripts, os.W_OK):
                reasons.append(f'The NSE update needs write access to {database}. '
                               "Set nmap_updatensedb = 'False' to skip it.")
    if enabled(rules.get('nmap_assumesudoperms_enable', False)):
        reasons.append("Privileged host discovery is enabled (nmap_assumesudoperms_enable).")
    if values is None:
        values = initial_values(tool, config)
    scan_method = values[16]
    for key, label in ((4, 'traceroute'), (6, 'OS detection'), (9, 'source address spoofing'),
                       (12, 'MAC spoofing'), (14, 'bad checksums')):
        if values[key]:
            reasons.append(f'Nmap needs raw packet privileges for {label}.')
    if scan_method and scan_method[0] != 'Connect() Scan':
        method = NMAP_SCAN_METHOD_LABELS.get(scan_method[0], scan_method[0])
        reasons.append(f'Nmap needs raw packet privileges for {method}.')
    return reasons


def privilege_message(reasons):
    """Format privilege reasons for an interactive Nmap launch.

    Join the reason strings with newlines and append the checkout-specific sudo
    invocation. The caller decides whether to prompt.
    """
    return '\n'.join([*reasons, 'To run with sudo from the checkout: sudo .venv/bin/python asadt.py run scantool nmap'])
