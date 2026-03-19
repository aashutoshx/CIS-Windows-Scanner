"""
Scanner Engine
Loads checklists and dispatches controls to the appropriate checker.
"""

import json
import os
import sys
import logging
from typing import List, Dict
from checkers.registry_checker import RegistryChecker
from checkers.service_checker import ServiceChecker
from checkers.policy_checker import SecurityPolicyChecker, AuditPolicyChecker
from checkers.network_checker import FirewallChecker, NetworkChecker
from checkers.base_checker import CheckResult

logger = logging.getLogger(__name__)

CHECKLIST_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "checklists")

# Maps check_type string → checker instance
CHECKER_REGISTRY = {
    "registry":        RegistryChecker(),
    "service":         ServiceChecker(),
    "security_policy": SecurityPolicyChecker(),
    "audit_policy":    AuditPolicyChecker(),
    "firewall":        FirewallChecker(),
    "network":         NetworkChecker(),
}

DEPTH_ORDER = {"essential": 1, "intermediate": 2, "deep": 3}


class Scanner:
    def __init__(self, system_type: str, depth: str):
        self.system_type = system_type
        self.depth = depth
        self.controls: List[dict] = []
        self._setup_logging()

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.WARNING,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            handlers=[logging.StreamHandler(sys.stderr)],
        )

    def load_checklist(self):
        """Load and filter controls from JSON checklists based on system type + depth."""
        # Load all depth levels up to and including selected
        depth_ceiling = DEPTH_ORDER[self.depth]
        all_controls = []

        for depth_name, depth_level in DEPTH_ORDER.items():
            if depth_level > depth_ceiling:
                continue
            path = os.path.join(CHECKLIST_DIR, f"{self.system_type}_{depth_name}.json")
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                    all_controls.extend(data.get("controls", []))
            else:
                logger.warning("Checklist not found: %s", path)

        # De-duplicate by control ID (deeper definitions take precedence)
        seen = {}
        for ctrl in all_controls:
            seen[ctrl["id"]] = ctrl
        self.controls = sorted(seen.values(), key=lambda c: c["id"])

    def run(self) -> List[dict]:
        """Execute all loaded controls and return result dicts."""
        results = []
        total = len(self.controls)

        for idx, control in enumerate(self.controls, 1):
            check_type = control.get("check_type", "")
            checker = CHECKER_REGISTRY.get(check_type)

            # Progress indicator
            status_char = "."
            print(f"  [{idx:3d}/{total}] {control['id']:<12} {control['name'][:55]:<55}", end=" ")

            if checker is None:
                result = CheckResult(
                    control_id=control.get("id", ""),
                    control_name=control.get("name", ""),
                    description=control.get("description", ""),
                    category=control.get("category", ""),
                    severity=control.get("severity", "Medium"),
                    status="Error",
                    observed_value=f"No checker for type: {check_type}",
                    remediation=control.get("remediation", ""),
                    references=control.get("references", ""),
                )
            else:
                result = checker.execute(control)

            status_char = {"Compliant": "✓", "Non-Compliant": "✗", "Error": "!"}.get(result.status, "?")
            print(status_char)
            results.append(result.to_dict())

        return results
