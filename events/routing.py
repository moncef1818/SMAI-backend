ML_ROUTING_MAP = {
    'NetworkMonitor':       'network',
    'BrowserExtension':       'browser',
}

def resolve_ml_target(log_source: str) -> str | None:
    return ML_ROUTING_MAP.get(log_source)