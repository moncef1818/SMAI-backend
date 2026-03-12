ML_ROUTING_MAP = {
    'NetworkMonitor':       'network',
    'FileIntegrityMonitor': 'filesystem',
    'ProcessMonitor':       'system',
}

def resolve_ml_target(log_source: str) -> str | None:
    return ML_ROUTING_MAP.get(log_source)