"""
Service Checker
Validates Windows service startup type and running state.
Uses 'sc query' and 'sc qc' via subprocess — no extra dependencies.
"""

import subprocess
import platform
import re
import logging
from checkers.base_checker import BaseChecker, CheckResult

logger = logging.getLogger(__name__)
_ON_WINDOWS = platform.system() == "Windows"

# Startup type integer → human-readable
STARTUP_MAP = {
    0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled",
    "boot": 0, "system": 1, "auto": 2, "automatic": 2,
    "manual": 3, "demand": 3, "disabled": 4,
}

STATE_MAP = {"running": "RUNNING", "stopped": "STOPPED", "paused": "PAUSED"}


class ServiceChecker(BaseChecker):
    name = "service"

    def _check(self, control: dict) -> CheckResult:
        params = control.get("check_params", {})
        service_name = params.get("service_name", "")
        expected_startup = params.get("expected_startup")      # e.g. "Disabled", "Manual"
        expected_state = params.get("expected_state")          # e.g. "Stopped", "Running"
        operator = params.get("operator", "eq")

        info = self._get_service_info(service_name)

        if info is None:
            # Service not found — check if that's acceptable
            if expected_startup and expected_startup.lower() == "not_installed":
                return self._make_result(control, True, "Service not installed",
                                         f"Service '{service_name}' not found on system")
            return self._make_result(control, False, "Service not found",
                                     f"Service '{service_name}' is not installed")

        observed_startup = info.get("startup", "Unknown")
        observed_state = info.get("state", "Unknown")
        observed_str = f"Startup={observed_startup}, State={observed_state}"
        evidence = f"Service: {service_name} | {observed_str}"

        # Evaluate startup type
        if expected_startup:
            is_compliant = self._evaluate(
                observed_startup.lower(), expected_startup.lower(), operator
            )
            return self._make_result(control, is_compliant, observed_str, evidence)

        # Evaluate running state
        if expected_state:
            is_compliant = self._evaluate(
                observed_state.lower(), expected_state.lower(), operator
            )
            return self._make_result(control, is_compliant, observed_str, evidence)

        return self._make_result(control, False, observed_str, "No expected value defined")

    def _get_service_info(self, service_name: str):
        if not _ON_WINDOWS:
            return self._simulate(service_name)
        try:
            config_out = subprocess.check_output(
                ["sc", "qc", service_name], text=True, stderr=subprocess.DEVNULL
            )
            state_out = subprocess.check_output(
                ["sc", "query", service_name], text=True, stderr=subprocess.DEVNULL
            )

            startup_match = re.search(r"START_TYPE\s*:\s*(\d+)\s*(\w+)", config_out)
            state_match = re.search(r"STATE\s*:\s*\d+\s*(\w+)", state_out)

            return {
                "startup": startup_match.group(2).capitalize() if startup_match else "Unknown",
                "state": state_match.group(1).upper() if state_match else "Unknown",
            }
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None

    @staticmethod
    def _simulate(service_name: str):
        _sim = {
            "RemoteRegistry":   {"startup": "Disabled", "state": "STOPPED"},
            "Spooler":          {"startup": "Manual",   "state": "STOPPED"},
            "Telnet":           {"startup": "Disabled", "state": "STOPPED"},
            "SNMP":             {"startup": "Disabled", "state": "STOPPED"},
            "W3SVC":            {"startup": "Disabled", "state": "STOPPED"},
            "WinRM":            {"startup": "Manual",   "state": "STOPPED"},
            "wuauserv":         {"startup": "Automatic","state": "RUNNING"},
            "MpsSvc":           {"startup": "Automatic","state": "RUNNING"},
            "EventLog":         {"startup": "Automatic","state": "RUNNING"},
            "SamSs":            {"startup": "Automatic","state": "RUNNING"},
        }
        return _sim.get(service_name)
