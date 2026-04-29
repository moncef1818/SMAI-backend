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
        
        logger.info(f"[EVENT INGEST] Event queued for processing")
        
        ingest_event.delay(
            host_id=str(request.user.id),
            data=serializer.validated_data,
        )

        return Response({"status": "queued"}, status=status.HTTP_202_ACCEPTED)