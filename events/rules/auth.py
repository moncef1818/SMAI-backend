from typing import Any, Dict, List
from .base import RuleResult, BaseEvaluator, Severity


class AuthEvaluator(BaseEvaluator):
    """
    Stateless authentication rules:
    - C-1a: Failed login attempts
    - C-1b: Account lockout
    - C-1c: Privilege escalation
    - C-1d: Password policy violations
    - C-1e: Unauthorized group changes
    - C-1f: Account deletion
    - C-1g: Multiple protocol logon
    - C-1h: Anomalous logon hours
    """

    def evaluate(self, payload: Dict[str, Any], host_id: str, event_id: str) -> List[RuleResult]:
        return [
            self._rule_c_1a(payload),
            self._rule_c_1b(payload),
            self._rule_c_1c(payload),
            self._rule_c_1d(payload),
            self._rule_c_1e(payload),
            self._rule_c_1f(payload),
            self._rule_c_1g(payload),
            self._rule_c_1h(payload),
        ]

    def _rule_c_1a(self, payload: Dict[str, Any]) -> RuleResult:
        """Failed login attempts threshold."""
        value = payload.get("FailedLoginCount")
        fired = self._null_safe_check(value) and value >= 5
        return RuleResult(
            rule_id="C-1a",
            fired=fired,
            severity=Severity.MEDIUM if fired else Severity.INFO,
            mitre="T1110.001",
            triggering_fields={"FailedLoginCount": value} if fired else {},
        )

    def _rule_c_1b(self, payload: Dict[str, Any]) -> RuleResult:
        """Account lockout detected."""
        event_type = payload.get("EventType")
        fired = event_type == "AccountLockout"
        return RuleResult(
            rule_id="C-1b",
            fired=fired,
            severity=Severity.MEDIUM if fired else Severity.INFO,
            mitre="T1531",
            triggering_fields={"EventType": event_type} if fired else {},
        )

    def _rule_c_1c(self, payload: Dict[str, Any]) -> RuleResult:
        """Privilege escalation attempt."""
        privilege_change = payload.get("PrivilegeChange")
        fired = privilege_change == "Admin"
        return RuleResult(
            rule_id="C-1c",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1134.002",
            triggering_fields={"PrivilegeChange": privilege_change} if fired else {},
        )

    def _rule_c_1d(self, payload: Dict[str, Any]) -> RuleResult:
        """Password policy violation."""
        password_age = payload.get("PasswordAge")
        fired = self._null_safe_check(password_age) and password_age > 365
        return RuleResult(
            rule_id="C-1d",
            fired=fired,
            severity=Severity.LOW if fired else Severity.INFO,
            mitre="T1556",
            triggering_fields={"PasswordAge": password_age} if fired else {},
        )

    def _rule_c_1e(self, payload: Dict[str, Any]) -> RuleResult:
        """Unauthorized group membership change."""
        group_added = payload.get("GroupAdded")
        sensitive_groups = ["Administrators", "Domain Admins", "Enterprise Admins"]
        fired = group_added in sensitive_groups
        return RuleResult(
            rule_id="C-1e",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1098",
            triggering_fields={"GroupAdded": group_added} if fired else {},
        )

    def _rule_c_1f(self, payload: Dict[str, Any]) -> RuleResult:
        """Account deletion detected."""
        event_type = payload.get("EventType")
        fired = event_type == "AccountDeleted"
        return RuleResult(
            rule_id="C-1f",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1531",
            triggering_fields={"EventType": event_type} if fired else {},
        )

    def _rule_c_1g(self, payload: Dict[str, Any]) -> RuleResult:
        """Multiple protocol logon (suspicious access patterns)."""
        protocols = payload.get("LogonProtocols", [])
        fired = len(set(protocols)) > 3 if isinstance(protocols, list) else False
        return RuleResult(
            rule_id="C-1g",
            fired=fired,
            severity=Severity.MEDIUM if fired else Severity.INFO,
            mitre="T1133",
            triggering_fields={"LogonProtocols": protocols} if fired else {},
        )

    def _rule_c_1h(self, payload: Dict[str, Any]) -> RuleResult:
        """Logon outside normal business hours."""
        logon_hour = payload.get("LogonHour")
        fired = self._null_safe_check(logon_hour) and (logon_hour < 6 or logon_hour > 22)
        return RuleResult(
            rule_id="C-1h",
            fired=fired,
            severity=Severity.LOW if fired else Severity.INFO,
            mitre="T1110",
            triggering_fields={"LogonHour": logon_hour} if fired else {},
        )