from typing import Any, Dict, List
import re
from .base import RuleResult, BaseEvaluator, Severity

class ProcessEvaluator(BaseEvaluator):
    """
    Stateless process rules:
    - A-1a: Malicious child of Office/Browser
    - A-1b: Unsigned binary in Temp/AppData/Downloads
    - A-1c: Suspicious CommandLine regex matches
    - A-4a: net.exe localgroup administrators
    - A-4b: Discovery commands
    """

    def evaluate(self, payload: Dict[str, Any], host_id: str, event_id: str) -> List[RuleResult]:
        return [
            self._rule_a_1a(payload),
            self._rule_a_1b(payload),
            self._rule_a_1c(payload),
            self._rule_a_4a(payload),
            self._rule_a_4b(payload),
        ]

    def _rule_a_1a(self, payload: Dict[str, Any]) -> RuleResult:
        event_type = payload.get("EventType", "")
        process_name = payload.get("ProcessName", "").lower()
        parent_chain = [p.lower() for p in payload.get("ParentChainNames", [])] if isinstance(payload.get("ParentChainNames"), list) else []

        targets = {"cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe"}
        parents = {"winword.exe","excel.exe","powerpnt.exe","outlook.exe","firefox.exe","chrome.exe","msedge.exe","acrord32.exe"}

        fired = event_type == "Start" and process_name in targets and any(p in parents for p in parent_chain)

        return RuleResult(
            rule_id="A-1a",
            fired=fired,
            severity=Severity.CRITICAL if fired else Severity.INFO,
            mitre="T1566.001",
            triggering_fields={"ProcessName": process_name, "ParentChainNames": parent_chain} if fired else {},
        )

    def _rule_a_1b(self, payload: Dict[str, Any]) -> RuleResult:
        event_type = payload.get("EventType", "")
        is_signed = payload.get("IsSigned")
        image_file_name = payload.get("ImageFileName", "").lower()
        
        suspicious_paths = [r"\temp\\", r"\appdata\\", r"\downloads\\"]
        
        # IsSigned=None means check wasn't performed; only fire on explicitly False
        fired = event_type == "Start" and is_signed is False and any(p in image_file_name for p in suspicious_paths)
        return RuleResult(
            rule_id="A-1b",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1204.002",
            triggering_fields={"ImageFileName": image_file_name, "IsSigned": is_signed} if fired else {},
        )

    def _rule_a_1c(self, payload: Dict[str, Any]) -> RuleResult:
        event_type = payload.get("EventType", "")
        cmd_line = payload.get("CommandLine", "")
        
        suspicious_patterns = [
            r"certutil.*-decode", r"certutil.*-urlcache", r"regsvr32.*/s",
            r"mshta.*http", r"rundll32.*,#", r"wmic.*process.*call.*create", r"bitsadmin.*/transfer"
        ]
        
        fired = event_type == "Start" and any(re.search(pattern, cmd_line, re.IGNORECASE) for pattern in suspicious_patterns)
        return RuleResult(
            rule_id="A-1c",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1218",
            triggering_fields={"CommandLine": cmd_line[:100]} if fired else {},
        )

    def _rule_a_4a(self, payload: Dict[str, Any]) -> RuleResult:
        process_name = payload.get("ProcessName", "").lower()
        cmd_line = payload.get("CommandLine", "").lower()
        parent_chain = [p.lower() for p in payload.get("ParentChainNames", [])] if isinstance(payload.get("ParentChainNames"), list) else []
        
        fired = (process_name == "net.exe" and "localgroup" in cmd_line and "administrators" in cmd_line and 
                 "explorer.exe" not in parent_chain and "cmd.exe" not in parent_chain)
                 
        return RuleResult(
            rule_id="A-4a",
            fired=fired,
            severity=Severity.MEDIUM if fired else Severity.INFO,
            mitre="T1069.001",
            triggering_fields={"CommandLine": cmd_line, "ParentChainNames": parent_chain} if fired else {},
        )

    def _rule_a_4b(self, payload: Dict[str, Any]) -> RuleResult:
        process_name = payload.get("ProcessName", "").lower()
        cmd_line = payload.get("CommandLine", "").lower()
        parent_chain = [p.lower() for p in payload.get("ParentChainNames", [])] if isinstance(payload.get("ParentChainNames"), list) else []
        
        targets = {"whoami.exe","ipconfig.exe","systeminfo.exe","net.exe","nltest.exe"}
        args = ["/all","domain","/priv"]
        
        fired = (process_name in targets and any(arg in cmd_line for arg in args) and
                 any(p in ["cmd.exe", "powershell.exe", "pwsh.exe"] for p in parent_chain) and "explorer.exe" not in parent_chain)
                 
        return RuleResult(
            rule_id="A-4b",
            fired=fired,
            severity=Severity.MEDIUM if fired else Severity.INFO,
            mitre="T1082",
            triggering_fields={"CommandLine": cmd_line, "ParentChainNames": parent_chain} if fired else {},
        )