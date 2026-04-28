import logging
from .base import RuleResult
from .network import NetworkEvaluator
from .auth import AuthEvaluator
from .process import ProcessEvaluator
from .filesystem import FileSystemEvaluator
from .registry import RegistryEvaluator
from .usb import UsbEvaluator

logger = logging.getLogger(__name__)


class RuleDispatcher:
    """Routes event payloads to the correct rule evaluator based on log_source."""

    EVALUATORS = {
        "NetworkMonitor": NetworkEvaluator,
        "AuthMonitor": AuthEvaluator,
        "ProcessMonitor": ProcessEvaluator,
        "FileMonitor": FileSystemEvaluator,
        "RegistryMonitor": RegistryEvaluator,
        "UsbMonitor": UsbEvaluator,
    }

    @staticmethod
    def dispatch(log_source, payload, host_id, event_id):
        evaluator_class = RuleDispatcher.EVALUATORS.get(log_source)
        if not evaluator_class:
            logger.warning(f"[DISPATCHER] No evaluator for log_source='{log_source}'")
            return []
        try:
            evaluator = evaluator_class()
            results = evaluator.evaluate(payload, host_id, event_id)
            logger.info(f"[DISPATCHER] {log_source}: {len([r for r in results if r.fired])} rules fired")
            return results
        except Exception as e:
            logger.error(f"[DISPATCHER] Error evaluating {log_source}: {e}")
            return []