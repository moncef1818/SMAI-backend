from .base import BaseEvaluator, RuleResult, Severity

class NetworkEvaluator(BaseEvaluator):

    """
    Stateless network rules:
    - B-1a: IatCoefficientOfVariation
    - B-1c: ExfiltrationZScore
    - B-2a: ASYMMETRIC / ONE-WAY FLOW
    - B-2b: LONG-DURATION IDLE FLOWS (C2 PERSISTENCE)
    - B-2c: ANOMALOUS TCP FLAG PATTERNS
    - B-2d: 
    - B-2e: LARGE PACKET / TUNNELLING
    - B-2f: ABNORMAL INITIAL WINDOW SIZE
    """
        


    def evaluate(self, payload,host_id,event_id):
        return [
            self._rule_b_1a(payload),
            self._rule_b_1c(payload),
            self._rule_b_2a(payload),
            self._rule_b_2b(payload),
            self._rule_b_2c(payload),
            self._rule_b_2d(payload),
            self._rule_b_2e(payload),
            self._rule_b_2f(payload)
        ]
    
    def _rule_b_1a(self,payload):
        value = payload.get("IatCoefficientOfVariation")
        fired = self._null_safe_check(value) and value < 0.1
        return RuleResult(
            rule_id="B-1a",
            fired=fired,
            severity=Severity.CRITICAL if fired else Severity.INFO,
            mitre="T1071.001",
            triggering_fields={"IatCoefficientOfVariation": value} if fired else {}
            )



    def _rule_b_1c(self,payload):
        value = payload.get("ExfiltrationZScore")
        fired = self._null_safe_check(value) and value > 3.0

        return RuleResult(
            rule_id="B-1c",
            fired=fired,
            severity=Severity.CRITICAL if fired else Severity.INFO,
            mitre="T1041",
            triggering_fields={"ExfiltrationZScore": value} if fired else {}
        )
    
    def _rule_b_2a(self,payload):

        BwdPackets = payload.get("BwdPackets")
        FwdPackets = payload.get("FwdPackets")
        FwdBytes = payload.get("FwdBytes")

        fired = False
        if all(self._null_safe_check(v) for v in (BwdPackets, FwdPackets, FwdBytes)):
            fired = BwdPackets == 0 and FwdPackets >= 5 and FwdBytes >= 10240

        return RuleResult(
            rule_id="B-2a",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1041",
            triggering_fields={
                                "BwdPackets": BwdPackets,
                                "FwdPackets": FwdPackets,
                                "FwdBytes": FwdBytes
                            } if fired else {}  
        )
    
    def _rule_b_2b(self,payload):

        Protocol = payload.get("Protocol")
        FlowDuration = payload.get("FlowDuration")
        FlowBytesPerSec = payload.get("FlowBytesPerSec")

        fired = False
        if all(self._null_safe_check(v) for v in (Protocol, FlowDuration, FlowBytesPerSec)):
            fired = Protocol == 6 and FlowDuration >= 60000000 and FlowBytesPerSec < 100
        return RuleResult(
            rule_id="B-2b",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1071.001",
            triggering_fields={
                                "Protocol": Protocol,
                                "FlowDuration": FlowDuration,
                                "FlowBytesPerSec": FlowBytesPerSec
                            } if fired else {}  
        )
    
    def _rule_b_2c(self,payload):

        RstCount = payload.get("RstCount")
        SynCount = payload.get("SynCount")
        AckCount = payload.get("AckCount")
        FinCount = payload.get("FinCount")

        fired = False
        if all(self._null_safe_check(v) for v in (RstCount, SynCount, AckCount, FinCount)):
            fired = RstCount >= 5 and SynCount >= 5 and AckCount == 0 and FinCount == 0

        return RuleResult(
            rule_id="B-2c",
            fired=fired,
            severity=Severity.HIGH if fired else Severity.INFO,
            mitre="T1046",
            triggering_fields={
                                "RstCount": RstCount,
                                "SynCount": SynCount,
                                "AckCount": AckCount,
                                "FinCount": FinCount
                            } if fired else {}  
        )
    
    def _rule_b_2d(self,payload):

        UrgCount = payload.get("UrgCount")
        FwdPackets = payload.get("FwdPackets")

        fired = False
        if all(self._null_safe_check(v) for v in (UrgCount, FwdPackets)):
            fired = UrgCount > 0 and UrgCount >= 0.5 * FwdPackets

        return RuleResult(
            rule_id="B-2d",
            fired=fired,
            severity=Severity.CRITICAL if fired else Severity.INFO,
            mitre="T1205",
            triggering_fields={
                                "UrgCount": UrgCount,
                                "FwdPackets": FwdPackets
                            } if fired else {}
        )
    
    def _rule_b_2e(self,payload):

        Protocol = payload.get("Protocol")
        AvgPktSize = payload.get("AvgPktSize")
        FwdPktLenMin = payload.get("FwdPktLenMin")

        fired = False
        if all(self._null_safe_check(v) for v in (Protocol, AvgPktSize, FwdPktLenMin)):
            fired = Protocol == 17 and AvgPktSize > 1200 and FwdPktLenMin > 900

        return RuleResult(
            rule_id="B-2e",
            fired=fired,
            severity=Severity.MEDIUM if fired else Severity.INFO,
            mitre="T1048.003",
            triggering_fields={
                                "Protocol": Protocol,
                                "AvgPktSize": AvgPktSize,
                                "FwdPktLenMin": FwdPktLenMin
                            } if fired else {}
        )
    
    def _rule_b_2f(self,payload):

        Protocol = payload.get("Protocol")
        SynCount = payload.get("SynCount")
        InitWinBytesFwd = payload.get("InitWinBytesFwd")

        fired = False
        if all(self._null_safe_check(v) for v in (Protocol, SynCount, InitWinBytesFwd)):
            fired = Protocol == 6 and SynCount >= 1 and InitWinBytesFwd < 1024 and InitWinBytesFwd > 0

        return RuleResult(
            rule_id="B-2f",
            fired=fired,
            severity=Severity.MEDIUM if fired else Severity.INFO,
            mitre="T1071.001",
            triggering_fields={
                                "Protocol": Protocol,
                                "SynCount": SynCount,
                                "InitWinBytesFwd": InitWinBytesFwd
                            } if fired else {}
        )