from urllib import request

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from hosts.authentication import HostAPIKeyAuthentication
from .serializers import EventIngestSerializer
from .models import Event
from .tasks import ingest_event

import logging

logger = logging.getLogger(__name__)


class EventIngestView(APIView):

    authentication_classes = [HostAPIKeyAuthentication]
    permission_classes = [IsAuthenticated]


    def post(self,request):



        serializer = EventIngestSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        ingest_event.delay(
            host_id=str(request.user.id),
            data=serializer.validated_data,
        )

        return Response({"status": "queued"}, status=status.HTTP_202_ACCEPTED)


