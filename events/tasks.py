from celery import shared_task
from django.utils import timezone
import logging
import requests
import json
import os

logger = logging.getLogger(__name__)
ML_SERVICE_URL = os.getenv("ML_SERVICE_URL", "http://ml:9871")
BROWSER_ML_SERVICE_URL = os.getenv("BROWSER_ML_SERVICE_URL", "http://browser-ml:9872")


@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=5,
)
def ingest_event(self, host_id: str, data: dict):
    try:
        from .models import Event
        from hosts.models import Host

        host = Host.objects.get(id=host_id)

        event = Event.objects.create(
            host=host,
            source_type=data['source_type'],
            log_source=data['log_source'],
            event_type=data['event_type'],
            payload=data['payload'],
        )

        host.last_seen = timezone.now()
        host.save()
        logger.info(f"[INGEST] Event {event.event_id} saved for host {host.hostname}")

        # Only dispatch rule engine here — it will chain to ML at the end
        run_rule_engine.delay(
            str(event.event_id),
            data['log_source'],
            data['payload'],
            str(host.id)
        )

    except Exception as exc:
        logger.error(f"[INGEST] Failed for host {host_id}: {exc}")
        raise self.retry(exc=exc)


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

            # TODO: broadcast incidents via websockets

    except Exception as e:
        logger.error(f"[RULES] Failed to evaluate {event_id}: {e}")

    # Always route to ML after rules, regardless of outcome
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
        'browser':    analyze_browser,
    }

    # Dispatch as a Celery task, not a plain function call
    task_map[target].delay(event_id, payload)
    logger.info(f"[ROUTE] Event {event_id} → {target}")


@shared_task
def analyze_network(event_id: str, payload: dict):
    """Send network payload to ML service on port 9871."""
    logger.info(f"[ML:NETWORK] Starting analysis for event {event_id}")
    
    try:
        # Prepare request to ML service
        ml_request = {
            "event_id": event_id,
            "payload": payload
        }
        
        logger.debug(f"[ML:NETWORK] Sending to {ML_SERVICE_URL}/predict")
        
        # Send to ML service
        response = requests.post(
            f"{ML_SERVICE_URL}/predict",
            json=ml_request,
            timeout=30
        )
        
        response.raise_for_status()
        ml_result = response.json()
        
        logger.info(f"[ML:NETWORK] Raw response: {json.dumps(ml_result)}")
        
        # Extract ML prediction data
        threat_score = ml_result.get('threat_score', 0.0)
        predicted_class = ml_result.get('ml_prediction', {}).get('predicted_class', 'UNKNOWN')
        probabilities = ml_result.get('ml_prediction', {}).get('probabilities', {})
        recommended_action = ml_result.get('recommended_action', '')
        
        logger.info(f"[ML:NETWORK] Threat Score: {threat_score}")
        logger.info(f"[ML:NETWORK] Class: {predicted_class}")
        logger.info(f"[ML:NETWORK] Action: {recommended_action}")
        
        # Create incident if threat_score is concerning
        if threat_score >= 0.3:
            create_ml_incident.delay(event_id, threat_score, predicted_class, probabilities, ml_result)
        else:
            logger.info(f"[ML:NETWORK] Threat score {threat_score} below threshold, no incident created")
        
    except requests.exceptions.Timeout:
        logger.error(f"[ML:NETWORK] Timeout connecting to ML service for {event_id}")
    except requests.exceptions.ConnectionError:
        logger.error(f"[ML:NETWORK] Connection error to ML service for {event_id}")
    except requests.exceptions.HTTPError as e:
        logger.error(f"[ML:NETWORK] HTTP error {response.status_code} for {event_id}: {response.text}")
    except Exception as e:
        logger.error(f"[ML:NETWORK] Error analyzing {event_id}: {e}")




@shared_task
def analyze_browser(event_id: str, payload: dict):
    """Send browser payload to browser ML service and create/update incident."""
    logger.info(f"[ML:BROWSER] Starting analysis for event {event_id}")

    try:
        response = requests.post(
            f"{BROWSER_ML_SERVICE_URL}/predict",
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        ml_result = response.json()

        logger.info(f"[ML:BROWSER] Raw response: {json.dumps(ml_result)}")

        verdict = ml_result.get("verdict", "UNKNOWN")
        risk = ml_result.get("risk", "low")
        ml_probability = ml_result.get("ml_probability", 0.0)
        rule_score = ml_result.get("rule_score", 0)
        triggered_rules = ml_result.get("triggered_rules", [])

        logger.info(f"[ML:BROWSER] verdict={verdict} risk={risk} probability={ml_probability}")

        if verdict in ["PHISHING", "SUSPICIOUS"] or risk in ["high", "critical"]:
            create_browser_ml_incident.delay(
                event_id,
                verdict,
                risk,
                ml_probability,
                rule_score,
                triggered_rules,
                ml_result,
            )
        else:
            logger.info(f"[ML:BROWSER] No incident created for event {event_id}: verdict={verdict}, risk={risk}")

    except requests.exceptions.Timeout:
        logger.error(f"[ML:BROWSER] Timeout connecting to browser ML service for {event_id}")
    except requests.exceptions.ConnectionError:
        logger.error(f"[ML:BROWSER] Connection error to browser ML service for {event_id}")
    except requests.exceptions.HTTPError as exc:
        logger.error(f"[ML:BROWSER] HTTP error {response.status_code} for {event_id}: {response.text}")
    except Exception as exc:
        logger.error(f"[ML:BROWSER] Error analyzing {event_id}: {exc}")

@shared_task
def create_ml_incident(event_id: str, threat_score: float, predicted_class: str, probabilities: dict, ml_result: dict):
    """Create or update incident from ML prediction."""
    from .models import Event
    from incidents.models import Incident
    
    try:
        event = Event.objects.get(event_id=event_id)
        
        # Determine severity based on threat_score
        if threat_score >= 0.9:
            severity = 'critical'
        elif threat_score >= 0.6:
            severity = 'high'
        elif threat_score >= 0.3:
            severity = 'medium'
        else:
            severity = 'low'
        
        # Map predicted class to MITRE technique
        mitre_mapping = {
            'BruteForce': 'T1110',
            'DDoS': 'T1498',
            'DoS': 'T1499',
            'PortScan': 'T1046',
            'Web Attack – Brute Force': 'T1110.003',
            'Web Attack – Sql Injection': 'T1190',
            'Web Attack – XSS': 'T1190',
            'Bot': 'T1071',
            'Infiltration': 'T1041',
            'BENIGN': 'N/A',
        }
        
        mitre = mitre_mapping.get(predicted_class, 'T1071')
        
        # Prepare high-risk detections
        high_risk_detections = []
        for class_name, probability in probabilities.items():
            if probability > 0.2 and class_name.upper() != 'BENIGN':
                high_risk_detections.append({
                    'class': class_name,
                    'probability': probability
                })
        
        ml_data = {
            'threat_score': threat_score,
            'predicted_class': predicted_class,
            'probabilities': probabilities,
            'high_risk_detections': high_risk_detections,
            'recommended_action': ml_result.get('recommended_action', ''),
            'flow_info': ml_result.get('flow_id', {}),
        }
        
        # Check if incident already exists for this event
        existing_incident = Incident.objects.filter(event=event).first()
        
        if existing_incident:
            # Update existing incident — merge data
            logger.info(f"[ML:INCIDENT] Found existing incident {existing_incident.incident_id} for event {event_id}")
            
            # Merge ML data into existing ai_summary
            updated_summary = existing_incident.ai_summary or {}
            updated_summary['ml_analysis'] = ml_data
            
            # Update severity to higher of the two
            severity_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
            existing_severity_level = severity_order.get(existing_incident.severity, 0)
            new_severity_level = severity_order.get(severity, 0)
            
            if new_severity_level > existing_severity_level:
                existing_incident.severity = severity
            
            # Update threat_type to include both sources if not already
            if 'rule+ml' not in existing_incident.threat_type:
                existing_incident.threat_type = f"{existing_incident.threat_type}+ML-{predicted_class}"
            
            existing_incident.ai_summary = updated_summary
            existing_incident.save()
            
            # Update event detection_source to "both"
            if event.detection_source != "both":
                event.detection_source = "both"
                event.save()
            
            logger.info(f"[ML:INCIDENT] Updated incident {existing_incident.incident_id} with ML data")
            logger.info(f"[ML:INCIDENT] New severity: {existing_incident.severity}, Threat type: {existing_incident.threat_type}")
            
        else:
            # Create new incident
            logger.info(f"[ML:INCIDENT] No existing incident for event {event_id}, creating new one")
            
            incident = Incident.objects.create(
                host=event.host,
                event=event,
                threat_type=f"ML-{predicted_class}",
                threat_source="ml",
                severity=severity,
                mitre=mitre,
                ai_summary=ml_data
            )
            
            event.detection_source = "ml"
            event.save()
            
            logger.info(f"[ML:INCIDENT] Created incident {incident.incident_id} for event {event_id}")
        
        logger.info(f"[ML:INCIDENT] Final severity: {severity}, Score: {threat_score}, Class: {predicted_class}")
        
        # TODO: Broadcast incident via WebSocket
        
    except Event.DoesNotExist:
        logger.error(f"[ML:INCIDENT] Event {event_id} not found")
    except Exception as e:
        logger.error(f"[ML:INCIDENT] Error creating/updating incident for {event_id}: {e}")

@shared_task
def create_browser_ml_incident(
    event_id: str,
    verdict: str,
    risk: str,
    ml_probability: float,
    rule_score: int,
    triggered_rules: list,
    ml_result: dict,
):
    from .models import Event
    from incidents.models import Incident

    try:
        event = Event.objects.get(event_id=event_id)

        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }
        severity = severity_map.get(risk, "medium")

        ai_summary = {
            "ml_verdict": verdict,
            "risk": risk,
            "ml_probability": ml_probability,
            "rule_score": rule_score,
            "triggered_rules": triggered_rules,
            "ml_response": ml_result,
        }

        existing_incident = Incident.objects.filter(event=event).first()

        if existing_incident:
            logger.info(f"[ML:BROWSER] Updating existing incident {existing_incident.incident_id}")
            summary = existing_incident.ai_summary or {}
            summary["browser_ml"] = ai_summary

            severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            if severity_order.get(severity, 0) > severity_order.get(existing_incident.severity, 0):
                existing_incident.severity = severity

            if "ML" not in existing_incident.threat_type:
                existing_incident.threat_type = f"{existing_incident.threat_type}+ML-BROWSER"

            existing_incident.ai_summary = summary
            existing_incident.save()

            if event.detection_source != "both":
                event.detection_source = "both"
                event.save()

        else:
            Incident.objects.create(
                host=event.host,
                event=event,
                threat_type=f"ML-BROWSER-{verdict}",
                threat_source="ml",
                severity=severity,
                mitre="N/A",
                ai_summary=ai_summary,
            )
            event.detection_source = "ml"
            event.save()

        logger.info(f"[ML:BROWSER] Incident processed for event {event_id}")

    except Event.DoesNotExist:
        logger.error(f"[ML:BROWSER] Event {event_id} not found")
    except Exception as exc:
        logger.error(f"[ML:BROWSER] Error creating/updating incident for {event_id}: {exc}")