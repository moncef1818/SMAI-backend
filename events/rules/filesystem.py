from typing import Any, Dict, List
from .base import RuleResult, BaseEvaluator, Severity


class FileSystemEvaluator(BaseEvaluator):
    """
    File system rules:
    - A-4d: Suspicious file extension
    - A-4e: Large file write event
    - A-4c: Sliding window file writes (requires Redis state - implement later)
    """

    SUSPICIOUS_EXTENSIONS = [
        ".exe", ".dll", ".scr", ".vbs", ".js", ".bat", ".cmd",
        ".lnk", ".msi", ".hta", ".pst", ".eml"
    ]

    def evaluate(self, payload: Dict[str, Any], host_id: str, event_id: str) -> List[RuleResult]:
        return [
            self._rule_a_4d(payload),
            self._rule_a_4e(payload),
        ]

    def _rule_a_4d(self, payload: Dict[str, Any]) -> RuleResult:
        """Suspicious file extension written to system directories."""
        file_path = payload.get("FilePath", "").lower()
        system_dirs = [r"windows\system32", r"windows\syswow64", r"programfiles"]
        in_system = any(sysdir in file_path for sysdir in system_dirs)
        
        has_suspicious_ext = any(file_path.endswith(ext.lower()) for ext in self.SUSPICIOUS_EXTENSIONS)
        
        fired = in_system and has_suspicious_ext
        return RuleResult(
            rule_id="A-4d",
            fired=fired,
            severity=Severity.CRITICAL if fired else Severity.INFO,
            mitre="T1574.001",
            triggering_fields={"FilePath": file_path} if fired else {},
        )

    def _rule_a_4e(self, payload: Dict[str, Any]) -> RuleResult:
        """Large file write event (potential data exfiltration)."""
        bytes_written = payload.get("BytesWritten")
        fired = self._null_safe_check(bytes_written) and bytes_written > 104857600  # > 100MB
        return RuleResult(
            rule_id="A-4e",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1041",
            triggering_fields={"BytesWritten": bytes_written} if fired else {},
        )