from celery import shared_task
from django.utils import timezone
import logging


logger = logging.getLogger(__name__)

@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=5,
)
def ingest_event(self , host_id: str,data: dict):
    try:
        from .models import Event
        from hosts.models import Host

        host = Host.objects.get(id=host_id)

        event = Event.objects.create(
            host = host,
            source_type = data['source_type'],
            log_source = data['log_source'],
            event_type =data['event_type'],
            payload = data['payload'],
        )
        
        host.last_seen = timezone.now()
        host.save()
        logger.info(f"[INGEST] Event {event.event_id} saved for host {host.hostname}")

        run_rule_engine.delay(str(event.event_id), data['log_source'], data['payload'], str(host.id))
    except Exception as exc:
        logger.error(f"[INGEST] Failed for host {host_id}: {exc}")
        raise self.retry(exc=exc)

    route_to_ml.delay(str(event.event_id), data['log_source'], data['payload'])


@shared_task
def run_rule_engine(event_id: str, log_source: str, payload: dict, host_id: str):

    from .models import Event
    from .rules.dispatcher import RuleDispatcher
    from incidents.models import Incident

    try:
        event = Event.objects.get(event_id=event_id)
        results = RuleDispatcher.dispatch(log_source, payload, host_id, event_id)

        fired_results = [r for r in results if r.fired]
        if fired_results:
            event.rule_triggered = True
            event.detection_source = "rule"
            event.save()

            for result in fired_results:
                Incident.objects.create(
                    host_id=host_id,
                    event=event,
                    threat_type=result.rule_id,
                    threat_source="rule",
                    severity=result.severity.value,
                    ai_summary=result.triggering_fields
                )
                logger.info(f"[RULES] Incident created: {result.rule_id} on host {host_id}")
            
            # TODO: brodcast incidents via websockets

    except Exception as e:
        logger.error(f"[RULES] Failed to evaluate {event_id}: {e}")

    route_to_ml.delay(event_id, log_source, payload)



@shared_task
def route_to_ml(event_id: str, log_source: str, payload: dict):
    from .routing import resolve_ml_target

    target = resolve_ml_target(log_source)

    if target is None:
        logger.warning(f"[ROUTE] No ML target for '{log_source}'. Skipping.")
        return
    
    task_map = {
        'network':    analyze_network,
        'filesystem': analyze_filesystem,
        'system':     analyze_system,
    }
    task_map[target](event_id, payload)
    logger.info(f"[ROUTE] Event {event_id} → {target}")

@shared_task
def analyze_network(event_id: str, payload: dict):
    logger.info(f"[ML:NETWORK] Analyzing event {event_id} — (mocked)")
    # TODO kykmlha sami

@shared_task
def analyze_filesystem(event_id: str, payload: dict):
    logger.info(f"[ML:FILESYSTEM] Analyzing event {event_id} — (mocked)")
    # TODO kykmlha sami

@shared_task
def analyze_system(event_id: str, payload: dict):
    logger.info(f"[ML:SYSTEM] Analyzing event {event_id} — (mocked)")
    # TODO kykmlha sami