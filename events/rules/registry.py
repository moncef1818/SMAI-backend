from typing import Any, Dict, List
from .base import RuleResult, BaseEvaluator, Severity


class RegistryEvaluator(BaseEvaluator):
    """
    Registry modification rules:
    - A-5a: Run key persistence
    - A-5b: Startup folder modification
    - A-5e: Registry value delete (anti-forensics)
    """

    RUN_KEYS = [
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKU\*\Software\Microsoft\Windows\CurrentVersion\Run",
    ]

    def evaluate(self, payload: Dict[str, Any], host_id: str, event_id: str) -> List[RuleResult]:
        return [
            self._rule_a_5a(payload),
            self._rule_a_5b(payload),
            self._rule_a_5e(payload),
        ]

    def _rule_a_5a(self, payload: Dict[str, Any]) -> RuleResult:
        """Registry Run key modification (persistence)."""
        reg_path = payload.get("RegistryPath", "").upper()
        fired = any(run_key.upper() in reg_path for run_key in self.RUN_KEYS)
        return RuleResult(
            rule_id="A-5a",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1547.001",
            triggering_fields={"RegistryPath": reg_path} if fired else {},
        )

    def _rule_a_5b(self, payload: Dict[str, Any]) -> RuleResult:
        """Startup folder modification."""
        file_path = payload.get("FilePath", "").lower()
        startup_dirs = [
            r"startup", r"\start menu\programs\startup",
            r"programdata\microsoft\windows\start menu"
        ]
        fired = any(startup_dir in file_path for startup_dir in startup_dirs)
        return RuleResult(
            rule_id="A-5b",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1547.009",
            triggering_fields={"FilePath": file_path} if fired else {},
        )

    def _rule_a_5e(self, payload: Dict[str, Any]) -> RuleResult:
        """Registry value deletion (anti-forensics)."""
        event_type = payload.get("EventType")
        fired = event_type == "RegistryDeleted"
        return RuleResult(
            rule_id="A-5e",
            fired=fired,
            severity=Severity.MEDIUM if fired else Severity.INFO,
            mitre="T1070.005",
            triggering_fields={"EventType": event_type} if fired else {},
        )