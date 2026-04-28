from typing import Any, Dict, List
from .base import RuleResult, BaseEvaluator, Severity
import logging

logger = logging.getLogger(__name__)


class UsbEvaluator(BaseEvaluator):
    """
    USB device rules:
    - D-2: USB insert on server class host
    - D-1a: Blocklisted VID/PID device
    - D-3: HID device insertion
    - D-1b: First-seen device with bulk data write
    - D-1c: First-seen device with sensitive file count
    - D-1d: First-seen device inserted outside business hours
    - D-1e: High-speed USB data transfer
    - D-1f: Rapid data transfer to USB (< 60s for 500MB)
    - D-1g: AutoExec/autorun script detected on USB
    """

    def evaluate(self, payload: Dict[str, Any], host_id: str, event_id: str) -> List[RuleResult]:
        logger.debug(f"Evaluating USB rules for host {host_id}, event {event_id} with payload: {payload}")
        return [
            self._rule_d_2(payload),
            self._rule_d_1a(payload),
            self._rule_d_3(payload),
            self._rule_d_1b(payload),
            self._rule_d_1c(payload),
            self._rule_d_1d(payload),
            self._rule_d_1e(payload),
            self._rule_d_1f(payload),
            self._rule_d_1g(payload),
        ]

    def _rule_d_2(self, payload: Dict[str, Any]) -> RuleResult:
        """USB device insertion on server-class host."""
        event_type = payload.get("EventType")
        insert_on_server = payload.get("InsertOnServerClassHost")
        fired = event_type == "Insert" and insert_on_server is True
        
        return RuleResult(
            rule_id="D-2",
            fired=fired,
            severity=Severity.CRITICAL if fired else Severity.INFO,
            mitre="T1052.001",
            triggering_fields={
                "EventType": event_type,
                "InsertOnServerClassHost": insert_on_server
            } if fired else {},
        )

    def _rule_d_1a(self, payload: Dict[str, Any]) -> RuleResult:
        """Blocklisted VID/PID device detected."""
        event_type = payload.get("EventType")
        vid_pid_blocklisted = payload.get("VidPidBlocklisted")
        blocklist_match = payload.get("BlocklistMatchName")
        fired = event_type == "Insert" and vid_pid_blocklisted is True
        
        return RuleResult(
            rule_id="D-1a",
            fired=fired,
            severity=Severity.CRITICAL if fired else Severity.INFO,
            mitre="T1200",
            triggering_fields={
                "EventType": event_type,
                "VidPidBlocklisted": vid_pid_blocklisted,
                "BlocklistMatchName": blocklist_match
            } if fired else {},
        )

    def _rule_d_3(self, payload: Dict[str, Any]) -> RuleResult:
        """HID device insertion (keyboard/mouse emulator risk)."""
        event_type = payload.get("EventType")
        device_is_hid = payload.get("DeviceClassIsHid")
        fired = event_type == "Insert" and device_is_hid is True
        
        return RuleResult(
            rule_id="D-3",
            fired=fired,
            severity=Severity.CRITICAL if fired else Severity.INFO,
            mitre="T1200",
            triggering_fields={
                "EventType": event_type,
                "DeviceClassIsHid": device_is_hid
            } if fired else {},
        )

    def _rule_d_1b(self, payload: Dict[str, Any]) -> RuleResult:
        """First-seen device with bulk data transfer (500MB+)."""
        event_type = payload.get("EventType")
        is_first_seen = payload.get("IsFirstSeen")
        total_bytes = payload.get("TotalBytesWritten")
        
        fired = (event_type == "Remove" and 
                 is_first_seen is True and 
                 self._null_safe_check(total_bytes) and 
                 total_bytes > 524288000)  # 500 MB
        
        return RuleResult(
            rule_id="D-1b",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1052.001",
            triggering_fields={
                "EventType": event_type,
                "IsFirstSeen": is_first_seen,
                "TotalBytesWritten": total_bytes
            } if fired else {},
        )

    def _rule_d_1c(self, payload: Dict[str, Any]) -> RuleResult:
        """First-seen device with high count of sensitive file extensions."""
        event_type = payload.get("EventType")
        is_first_seen = payload.get("IsFirstSeen")
        sensitive_ext_count = payload.get("SensitiveExtCount")
        
        fired = (event_type == "Remove" and 
                 is_first_seen is True and 
                 self._null_safe_check(sensitive_ext_count) and 
                 sensitive_ext_count > 50)
        
        return RuleResult(
            rule_id="D-1c",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1052.001",
            triggering_fields={
                "EventType": event_type,
                "IsFirstSeen": is_first_seen,
                "SensitiveExtCount": sensitive_ext_count
            } if fired else {},
        )

    def _rule_d_1d(self, payload: Dict[str, Any]) -> RuleResult:
        """First-seen device inserted outside business hours (23:00-05:59)."""
        event_type = payload.get("EventType")
        is_first_seen = payload.get("IsFirstSeen")
        insert_hour = payload.get("InsertHour")
        
        outside_business = (self._null_safe_check(insert_hour) and 
                           (insert_hour >= 23 or insert_hour <= 5))
        fired = (event_type in ["Insert", "Remove"] and 
                 is_first_seen is True and 
                 outside_business)
        
        return RuleResult(
            rule_id="D-1d",
            fired=fired,
            severity=Severity.MEDIUM if fired else Severity.INFO,
            mitre="T1052",
            triggering_fields={
                "EventType": event_type,
                "IsFirstSeen": is_first_seen,
                "InsertHour": insert_hour
            } if fired else {},
        )

    def _rule_d_1e(self, payload: Dict[str, Any]) -> RuleResult:
        """High-speed USB data transfer (> 50 MB/min)."""
        event_type = payload.get("EventType")
        bytes_per_min = payload.get("BytesToUsbPerMin")
        
        fired = (event_type == "Remove" and 
                 self._null_safe_check(bytes_per_min) and 
                 bytes_per_min > 50)  # MB/min
        
        return RuleResult(
            rule_id="D-1e",
            fired=fired,
            severity=Severity.MEDIUM if fired else Severity.INFO,
            mitre="T1052",
            triggering_fields={
                "EventType": event_type,
                "BytesToUsbPerMin": bytes_per_min
            } if fired else {},
        )

    def _rule_d_1f(self, payload: Dict[str, Any]) -> RuleResult:
        """Rapid data transfer: 500MB in < 60 seconds."""
        event_type = payload.get("EventType")
        time_to_500mb = payload.get("TimeTo500MbSec")
        
        fired = (event_type == "Remove" and 
                 self._null_safe_check(time_to_500mb) and 
                 time_to_500mb < 60)
        
        return RuleResult(
            rule_id="D-1f",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1052.001",
            triggering_fields={
                "EventType": event_type,
                "TimeTo500MbSec": time_to_500mb
            } if fired else {},
        )

    def _rule_d_1g(self, payload: Dict[str, Any]) -> RuleResult:
        """AutoExec/autorun script detected on USB device."""
        event_type = payload.get("EventType")
        autoexec_detected = payload.get("AutoExecScriptDetected")
        
        fired = (event_type in ["Insert", "Remove"] and 
                 autoexec_detected is True)
        
        return RuleResult(
            rule_id="D-1g",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1091",
            triggering_fields={
                "EventType": event_type,
                "AutoExecScriptDetected": autoexec_detected
            } if fired else {},
        )