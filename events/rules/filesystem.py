from typing import Any, Dict, List
from .base import RuleResult, BaseEvaluator, Severity

class FileSystemEvaluator(BaseEvaluator):
    """
    File system rules:
    - A-4d: DLL/EXE written to System32 by unusual process
    - A-4e: Ransomware extension change
    - A-4c: Sliding window file writes (requires Redis state - implement later)
    """

    def evaluate(self, payload: Dict[str, Any], host_id: str, event_id: str) -> List[RuleResult]:
        return [
            self._rule_a_4d(payload),
            self._rule_a_4e(payload),
        ]

    def _rule_a_4d(self, payload: Dict[str, Any]) -> RuleResult:
        event_type = payload.get("EventType", "")
        extension = payload.get("Extension", "").lower()
        file_path = payload.get("FilePath", "").lower()
        process_name = payload.get("ProcessName", "").lower()
        
        targets = {".exe", ".dll", ".sys"}
        allowed_procs = {"trustedinstaller.exe", "msiexec.exe", "wusa.exe", "svchost.exe"}
        
        fired = (event_type == "FileIO/Create" and extension in targets and
                 "\\system32\\" in file_path and process_name not in allowed_procs)
                 
        return RuleResult(
            rule_id="A-4d",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1574.001",
            triggering_fields={"FilePath": file_path, "ProcessName": process_name} if fired else {},
        )

    def _rule_a_4e(self, payload: Dict[str, Any]) -> RuleResult:
        event_type = payload.get("EventType", "")
        extension = payload.get("Extension", "").lower()
        
        ransom_exts = {
            ".locked", ".encrypted", ".enc", ".crypt", ".crypted", 
            ".locky", ".zepto", ".cerber", ".zzzzz", ".shit", ".thor", ".osiris"
        }
        
        fired = event_type == "FileIO/SetInfo" and extension in ransom_exts
        
        return RuleResult(
            rule_id="A-4e",
            fired=fired,
            severity=Severity.CRITICAL if fired else Severity.INFO,
            mitre="T1486",
            triggering_fields={"Extension": extension} if fired else {},
        )