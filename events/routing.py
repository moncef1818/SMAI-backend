from django.urls import re_path
from .consumers import IncidentConsumer

websocket_urlpatterns = [
    re_path(r'ws/incidents/$', IncidentConsumer.as_asgi()),
]

# ML routing map for task dispatch
ML_ROUTING_MAP = {
    'NetworkMonitor':       'network',
    'BrowserExtension':       'browser',
}

def resolve_ml_target(log_source: str) -> str | None:
    return ML_ROUTING_MAP.get(log_source)