from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from hosts.authentication import HostAPIKeyAuthentication
from .serializers import EventIngestSerializer
from .models import Event
from .tasks import ingest_event
import logging
import json

logger = logging.getLogger(__name__)


class EventIngestView(APIView):

    authentication_classes = [HostAPIKeyAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        
        # Log full request details
        logger.info(f"[EVENT INGEST] Request received")
        logger.info(f"  User: {request.user}")
        logger.info(f"  User type: {type(request.user)}")
        logger.info(f"  Is authenticated: {request.user.is_authenticated}")
        logger.info(f"  Remote IP: {request.META.get('REMOTE_ADDR')}")
        logger.info(f"  Content-Type: {request.META.get('CONTENT_TYPE')}")
        
        # Log headers
        auth_header = request.META.get('HTTP_AUTHORIZATION', 'None')
        logger.info(f"  Authorization header: {auth_header[:50] if auth_header else 'None'}...")
        
        logger.info(f"  Full headers: {dict(request.headers)}")
        logger.info(f"  Body: {request.data}")

        serializer = EventIngestSerializer(data=request.data)

        if not serializer.is_valid():
            logger.warning(f"[EVENT INGEST] Validation failed: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        if serializer.validated_data.get('log_source') == 'BrowserExtension':
            try:
                host = request.user
                event = Event.objects.create(
                    host=host,
                    source_type=serializer.validated_data['source_type'],
                    log_source=serializer.validated_data['log_source'],
                    event_type=serializer.validated_data['event_type'],
                    payload=serializer.validated_data['payload'],
                )
                host.last_seen = timezone.now()
                host.save()

                import requests
                import os
                from django.utils import timezone
                from .tasks import create_browser_ml_incident
                
                BROWSER_ML_SERVICE_URL = os.getenv("BROWSER_ML_SERVICE_URL", "http://browser-ml:9872")
                response = requests.post(f"{BROWSER_ML_SERVICE_URL}/predict", json=serializer.validated_data['payload'], timeout=10)
                response.raise_for_status()
                ml_result = response.json()

                verdict = ml_result.get("verdict", "UNKNOWN")
                risk = ml_result.get("risk", "low")
                prob = ml_result.get("ml_probability", 0.0)
                rule_score = ml_result.get("rule_score", 0)

                if verdict in ["PHISHING", "SUSPICIOUS"] or risk in ["high", "critical"]:
                    create_browser_ml_incident.delay(
                        str(event.event_id), verdict, risk, prob, rule_score,
                        ml_result.get("triggered_rules", []), ml_result
                    )
                
                # Convert ML probability to a 0-100 score for the extension
                final_score = int(prob * 100)
                if rule_score > final_score:
                    final_score = min(100, rule_score)

                return Response({
                    "isPhishing": verdict == "PHISHING",
                    "score": final_score,
                    "risk": risk,
                    "indicators": [r.get("rule") for r in ml_result.get("triggered_rules", [])],
                    "summary": f"Verdict: {verdict} (Risk: {risk.upper()})",
                    "analysisType": "ai"
                }, status=status.HTTP_200_OK)
            except Exception as e:
                logger.error(f"[EVENT INGEST] Browser ML synchronous error: {e}")
                # Fallback to queued if ML service fails
        
        logger.info(f"[EVENT INGEST] Event queued for processing")
        
        ingest_event.delay(
            host_id=str(request.user.id),
            data=serializer.validated_data,
        )

        return Response({"status": "queued"}, status=status.HTTP_202_ACCEPTED)