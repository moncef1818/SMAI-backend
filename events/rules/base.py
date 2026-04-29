from dataclasses import dataclass , field
from abc import ABC , abstractmethod
from typing import Any, Dict , List , Optional
from enum import Enum

class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class RuleResult:
    rule_id: str
    fired: bool
    severity: Severity
    mitre: str
    triggering_fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "fired": self.fired,
            "severity": self.severity.value,
            "mitre": self.mitre,
            "triggering_fields": self.triggering_fields,
        }
    
class BaseEvaluator(ABC):

    @abstractmethod
    def evaluate(self , payload: Dict[str, Any], host_id:str, event_id:str) -> List[RuleResult]:
        """
        Evaluate all rules in this evaluator against the given payload.
        
        Args:
            payload: The event payload from the agent (contains monitor fields)
            host_id: The host_id this event came from (needed for state/Redis lookups)
            event_id: The unique event_id (needed for dedup/state management)
            
        Returns:
            List of RuleResult objects (one per rule, fired or not).
            Only RuleResults with fired=True should be processed downstream.
        """
        pass

    def _null_safe_check(self , value:any) -> bool:
        return value is not None and value != ""
    
