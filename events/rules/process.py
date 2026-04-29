from typing import Any, Dict, List
import re
from .base import RuleResult, BaseEvaluator, Severity


class ProcessEvaluator(BaseEvaluator):
    """
    Stateless process rules:
    - A-1a: Suspicious parent-child process chain
    - A-1b: Unsigned executable execution
    - A-1c: Process name pattern matching (regex)
    - A-4a: Unusual process path
    - A-4b: Suspicious command-line arguments
    """

    SUSPICIOUS_PROCESSES = {
        "cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe",
        "mshta.exe", "regsvcs.exe", "regasm.exe", "rundll32.exe"
    }

    SUSPICIOUS_PARENTS = {
        "svchost.exe", "explorer.exe", "winlogon.exe", "services.exe"
    }

    SUSPICIOUS_COMMAND_KEYWORDS = [
        "cmd /c", "powershell -enc", "powershell -nop", "invoke-webrequest",
        "start-process", "regsvcs.exe", "rundll32.exe", "certutil.exe"
    ]

    def evaluate(self, payload: Dict[str, Any], host_id: str, event_id: str) -> List[RuleResult]:
        return [
            self._rule_a_1a(payload),
            self._rule_a_1b(payload),
            self._rule_a_1c(payload),
            self._rule_a_4a(payload),
            self._rule_a_4b(payload),
        ]

    def _rule_a_1a(self, payload: Dict[str, Any]) -> RuleResult:
        """Suspicious parent-child process chain."""
        process_name = payload.get("ProcessName", "").lower()
        parent_chain = payload.get("ParentChainNames", [])
        parent_chain = [p.lower() for p in parent_chain] if isinstance(parent_chain, list) else []

        fired = (process_name in self.SUSPICIOUS_PROCESSES and 
                 any(p in self.SUSPICIOUS_PARENTS for p in parent_chain))

        return RuleResult(
            rule_id="A-1a",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1059",
            triggering_fields={
                "ProcessName": process_name,
                "ParentChainNames": parent_chain
            } if fired else {},
        )

    def _rule_a_1b(self, payload: Dict[str, Any]) -> RuleResult:
        """Unsigned executable execution."""
        is_signed = payload.get("IsSigned")
        # IsSigned=None means check wasn't performed; only fire on explicitly False
        fired = is_signed is False
        return RuleResult(
            rule_id="A-1b",
            fired=fired,
            severity=Severity.CRITICAL if fired else Severity.INFO,
            mitre="T1036.005",
            triggering_fields={"IsSigned": is_signed} if fired else {},
        )

    def _rule_a_1c(self, payload: Dict[str, Any]) -> RuleResult:
        """Process name matches suspicious regex patterns."""
        process_name = payload.get("ProcessName", "")
        suspicious_patterns = [
            r".*temp.*\.exe",
            r".*appdata.*\.exe",
            r".*\d{8,}\.exe",  # Random numbers in name
            r".*[a-z]{20,}\.exe",  # Long random strings
        ]
        fired = any(re.match(pattern, process_name, re.IGNORECASE) for pattern in suspicious_patterns)
        return RuleResult(
            rule_id="A-1c",
            fired=fired,
            severity=Severity.MEDIUM if fired else Severity.INFO,
            mitre="T1036",
            triggering_fields={"ProcessName": process_name} if fired else {},
        )

    def _rule_a_4a(self, payload: Dict[str, Any]) -> RuleResult:
        """Unusual process execution path."""
        process_path = payload.get("ProcessPath", "").lower()
        suspicious_paths = [
            r"temp", r"appdata", r"programdata", r"windows\system32\drivers",
            r"recycle\.bin", r"$recycle\.bin"
        ]
        fired = any(suspect in process_path for suspect in suspicious_paths)
        return RuleResult(
            rule_id="A-4a",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1036.005",
            triggering_fields={"ProcessPath": process_path} if fired else {},
        )

    def _rule_a_4b(self, payload: Dict[str, Any]) -> RuleResult:
        """Suspicious command-line arguments."""
        cmd_line = payload.get("CommandLine", "").lower()
        fired = any(keyword in cmd_line for keyword in self.SUSPICIOUS_COMMAND_KEYWORDS)
        return RuleResult(
            rule_id="A-4b",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1086",
            triggering_fields={"CommandLine": cmd_line[:100]} if fired else {},
        )