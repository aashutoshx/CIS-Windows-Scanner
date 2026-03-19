"""
Base checker — all check modules inherit from this.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    control_id: str
    control_name: str
    description: str
    category: str
    status: str                          # "Compliant" | "Non-Compliant" | "Error"
    observed_value: Optional[str] = None
    expected_value: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    severity: str = "Medium"
    references: str = ""

    def to_dict(self) -> dict:
        return {
            "Control ID": self.control_id,
            "Control Name": self.control_name,
            "Description": self.description,
            "Category": self.category,
            "Severity": self.severity,
            "Status": self.status,
            "Expected Value": self.expected_value or "",
            "Observed Value": self.observed_value or "",
            "Evidence": self.evidence or "",
            "Remediation": self.remediation or "",
            "References": self.references or "",
        }


class BaseChecker(ABC):
    """Abstract base for all CIS check modules."""

    name: str = "base"

    def execute(self, control: dict) -> CheckResult:
        """Run a single control check, catching all errors gracefully."""
        try:
            return self._check(control)
        except Exception as exc:
            logger.warning("Check %s failed: %s", control.get("id"), exc)
            return CheckResult(
                control_id=control.get("id", "UNKNOWN"),
                control_name=control.get("name", "Unknown"),
                description=control.get("description", ""),
                category=control.get("category", ""),
                severity=control.get("severity", "Medium"),
                status="Error",
                observed_value=f"ERROR: {exc}",
                expected_value=self._describe_expected(control),
                remediation=control.get("remediation", ""),
                references=control.get("references", ""),
            )

    @abstractmethod
    def _check(self, control: dict) -> CheckResult:
        """Implement the actual check logic."""

    def _describe_expected(self, control: dict) -> str:
        p = control.get("check_params", {})
        op = p.get("operator", "eq")
        val = p.get("expected")
        op_map = {
            "eq": "==", "neq": "!=", "gte": ">=", "lte": "<=",
            "gt": ">", "lt": "<", "contains": "contains",
            "not_contains": "not contains", "exists": "exists",
            "not_exists": "not exists",
        }
        return f"{op_map.get(op, op)} {val}" if val is not None else op_map.get(op, op)

    @staticmethod
    def _evaluate(observed: Any, expected: Any, operator: str) -> bool:
        """Generic comparison operator."""
        try:
            if operator == "eq":
                return str(observed).lower() == str(expected).lower()
            if operator == "neq":
                return str(observed).lower() != str(expected).lower()
            if operator == "gte":
                return int(observed) >= int(expected)
            if operator == "lte":
                return int(observed) <= int(expected)
            if operator == "gt":
                return int(observed) > int(expected)
            if operator == "lt":
                return int(observed) < int(expected)
            if operator == "contains":
                return str(expected).lower() in str(observed).lower()
            if operator == "not_contains":
                return str(expected).lower() not in str(observed).lower()
            if operator == "exists":
                return observed is not None
            if operator == "not_exists":
                return observed is None
        except (TypeError, ValueError):
            return False
        return False

    def _make_result(self, control: dict, is_compliant: bool,
                     observed: str, evidence: str = "") -> CheckResult:
        return CheckResult(
            control_id=control["id"],
            control_name=control["name"],
            description=control.get("description", ""),
            category=control.get("category", ""),
            severity=control.get("severity", "Medium"),
            status="Compliant" if is_compliant else "Non-Compliant",
            observed_value=observed,
            expected_value=self._describe_expected(control),
            evidence=evidence,
            remediation=control.get("remediation", ""),
            references=control.get("references", ""),
        )
