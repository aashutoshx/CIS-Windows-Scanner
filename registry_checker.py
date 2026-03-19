"""
Registry Checker
Reads Windows registry values and compares against CIS expected values.
Uses winreg (built-in) — no extra dependencies required.
"""

import logging
import platform
from checkers.base_checker import BaseChecker, CheckResult

logger = logging.getLogger(__name__)

# Map string hive names → winreg constants
HIVE_MAP = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKU":  "HKEY_USERS",
    "HKCC": "HKEY_CURRENT_CONFIG",
}

_ON_WINDOWS = platform.system() == "Windows"

if _ON_WINDOWS:
    import winreg
    _HIVE_CONST = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKU":  winreg.HKEY_USERS,
        "HKCC": winreg.HKEY_CURRENT_CONFIG,
    }
else:
    _HIVE_CONST = {}


class RegistryChecker(BaseChecker):
    name = "registry"

    def _check(self, control: dict) -> CheckResult:
        params = control.get("check_params", {})
        hive_str = params.get("hive", "HKLM")
        key_path = params.get("key", "")
        value_name = params.get("value_name", "")
        expected = params.get("expected")
        operator = params.get("operator", "eq")

        observed_raw = self._read_registry(hive_str, key_path, value_name)

        if observed_raw is None:
            # Key/value does not exist
            if operator == "not_exists":
                return self._make_result(control, True, "Key not present", f"{hive_str}\\{key_path}\\{value_name}")
            return self._make_result(
                control, False,
                "Key/value not found",
                f"Registry path: {hive_str}\\{key_path} → '{value_name}' does not exist",
            )

        is_compliant = self._evaluate(observed_raw, expected, operator)
        evidence = f"Registry: {hive_str}\\{key_path}\\{value_name} = {observed_raw}"
        return self._make_result(control, is_compliant, str(observed_raw), evidence)

    def _read_registry(self, hive_str: str, key_path: str, value_name: str):
        if not _ON_WINDOWS:
            return self._simulate(hive_str, key_path, value_name)
        try:
            hive = _HIVE_CONST.get(hive_str.upper())
            if hive is None:
                raise ValueError(f"Unknown hive: {hive_str}")
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                value, _ = winreg.QueryValueEx(key, value_name)
                return value
        except FileNotFoundError:
            return None
        except PermissionError:
            raise PermissionError(f"Access denied reading {hive_str}\\{key_path}")

    @staticmethod
    def _simulate(hive_str: str, key_path: str, value_name: str):
        """
        Simulation layer for non-Windows environments (dev/testing).
        Returns plausible defaults so the tool can be tested cross-platform.
        Override this with actual data fixtures for unit tests.
        """
        _defaults = {
            ("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "ScreenSaverGracePeriod"): "5",
            ("HKLM", "SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters", "EnablePlainTextPassword"): 0,
            ("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Lsa", "LmCompatibilityLevel"): 5,
            ("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Lsa", "NoLMHash"): 1,
            ("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Lsa", "RestrictAnonymous"): 1,
            ("HKLM", "SYSTEM\\CurrentControlSet\\Control\\Lsa", "RestrictAnonymousSAM"): 1,
            ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "EnableLUA"): 1,
            ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "ConsentPromptBehaviorAdmin"): 2,
            ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "ConsentPromptBehaviorUser"): 0,
            ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "PromptOnSecureDesktop"): 1,
            ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "FilterAdministratorToken"): 1,
            ("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", "NoAutoUpdate"): 0,
            ("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", "AUOptions"): 4,
            ("HKLM", "SYSTEM\\CurrentControlSet\\Services\\RemoteRegistry", "Start"): 4,
            ("HKLM", "SYSTEM\\CurrentControlSet\\Services\\Spooler", "Start"): 4,
            ("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client", "AllowBasic"): 0,
            ("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service", "AllowBasic"): 0,
            ("HKLM", "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "UseLogonCredential"): 0,
            ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoDriveTypeAutoRun"): 255,
            ("HKLM", "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "EnableMulticast"): 0,
        }
        return _defaults.get((hive_str.upper(), key_path, value_name))
