"""
Security Policy Checker
Reads local security policy settings via secedit export and 'net accounts'.
Covers: password policy, account lockout, user rights assignments.
"""

import subprocess
import tempfile
import os
import re
import platform
import configparser
import logging
from checkers.base_checker import BaseChecker, CheckResult

logger = logging.getLogger(__name__)
_ON_WINDOWS = platform.system() == "Windows"


class SecurityPolicyChecker(BaseChecker):
    name = "security_policy"
    _policy_cache: dict = {}

    def _check(self, control: dict) -> CheckResult:
        params = control.get("check_params", {})
        policy_key = params.get("policy_key", "")
        section = params.get("section", "System Access")
        expected = params.get("expected")
        operator = params.get("operator", "eq")

        policy = self._get_policy(section)
        observed_raw = policy.get(policy_key.lower())

        if observed_raw is None:
            return self._make_result(control, False, "Policy key not found",
                                     f"Key '{policy_key}' not present in [{section}]")

        is_compliant = self._evaluate(observed_raw, expected, operator)
        evidence = f"[{section}] {policy_key} = {observed_raw}"
        return self._make_result(control, is_compliant, str(observed_raw), evidence)

    def _get_policy(self, section: str) -> dict:
        if section in self._policy_cache:
            return self._policy_cache[section]

        if not _ON_WINDOWS:
            data = self._simulate_all()
        else:
            data = self._export_secedit()

        self._policy_cache.update(data)
        return data.get(section, {})

    def _export_secedit(self) -> dict:
        try:
            with tempfile.NamedTemporaryFile(suffix=".cfg", delete=False) as f:
                tmp_path = f.name
            subprocess.run(
                ["secedit", "/export", "/cfg", tmp_path, "/quiet"],
                check=True, capture_output=True,
            )
            cfg = configparser.RawConfigParser()
            cfg.read(tmp_path, encoding="utf-16")
            result = {}
            for section in cfg.sections():
                result[section] = {k.lower(): v.strip() for k, v in cfg.items(section)}
            os.unlink(tmp_path)
            return result
        except Exception as exc:
            logger.warning("secedit export failed: %s", exc)
            return {}

    @staticmethod
    def _simulate_all() -> dict:
        return {
            "System Access": {
                "minimumpasswordage": "1",
                "maximumpasswordage": "60",
                "minimumpasswordlength": "14",
                "passwordcomplexity": "1",
                "passwordhistorysize": "24",
                "lockoutbadcount": "5",
                "lockoutduration": "15",
                "resetlockoutcount": "15",
                "requirelogontochangepassword": "0",
                "forceguestaccountas": "1",
                "lsaanonymousnamedpipes": "",
            },
            "Privilege Rights": {
                "seaccesscheckprivilege": "",
                "seauditprivilege": "*S-1-5-19,*S-1-5-20",
                "sebackupprivilege": "*S-1-5-32-544",
                "sechangenotifyprivilege": "*S-1-1-0,*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551",
                "seinteractivelogonright": "*S-1-5-32-544,*S-1-5-32-545",
                "senetworklogonright": "*S-1-1-0,*S-1-5-32-544,*S-1-5-32-545",
                "seremoteinteractivelogonright": "*S-1-5-32-544",
                "seshutdownprivilege": "*S-1-5-32-544",
            },
            "Registry Values": {
                "machine\\system\\currentcontrolset\\control\\lsa\\lmcompatibilitylevel": "4,5",
                "machine\\system\\currentcontrolset\\control\\lsa\\nolmhash": "4,1",
            },
        }


class AuditPolicyChecker(BaseChecker):
    """Checks Windows audit policy via auditpol.exe."""
    name = "audit_policy"
    _cache: dict = {}

    def _check(self, control: dict) -> CheckResult:
        params = control.get("check_params", {})
        category = params.get("category", "")
        subcategory = params.get("subcategory", "")
        expected = params.get("expected", "")   # e.g. "Success", "Failure", "Success and Failure"
        operator = params.get("operator", "contains")

        observed = self._get_audit_setting(subcategory or category)

        if observed is None:
            return self._make_result(control, False, "Audit setting not found",
                                     f"Subcategory '{subcategory}' not found via auditpol")

        is_compliant = self._evaluate(observed, expected, operator)
        evidence = f"Audit Policy: {subcategory or category} = {observed}"
        return self._make_result(control, is_compliant, observed, evidence)

    def _get_audit_setting(self, name: str):
        if not _ON_WINDOWS:
            return self._simulate(name)
        if name not in self._cache:
            self._cache.update(self._run_auditpol())
        return self._cache.get(name.lower())

    def _run_auditpol(self) -> dict:
        try:
            out = subprocess.check_output(
                ["auditpol", "/get", "/category:*"], text=True, stderr=subprocess.DEVNULL
            )
            result = {}
            for line in out.splitlines():
                parts = re.split(r'\s{2,}', line.strip())
                if len(parts) == 2:
                    result[parts[0].strip().lower()] = parts[1].strip()
            return result
        except Exception as exc:
            logger.warning("auditpol failed: %s", exc)
            return {}

    @staticmethod
    def _simulate(name: str) -> str:
        _sim = {
            "credential validation":         "Success and Failure",
            "account lockout":               "Failure",
            "logon":                         "Success and Failure",
            "logoff":                        "Success",
            "special logon":                 "Success",
            "audit policy change":           "Success and Failure",
            "authentication policy change":  "Success",
            "user account management":       "Success and Failure",
            "security group management":     "Success",
            "process creation":              "Success",
            "directory service access":      "Failure",
            "object access":                 "Failure",
            "privilege use":                 "Failure",
            "system integrity":              "Success and Failure",
            "security system extension":     "Success",
        }
        return _sim.get(name.lower(), "No Auditing")
