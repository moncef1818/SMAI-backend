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
    
    except Exception as exc:
        logger.error(f"[INGEST] Failed for host {host_id}: {exc}")
        raise self.retry(exc=exc)

    route_to_ml.delay(str(event.event_id), data['log_source'], data['payload'])

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