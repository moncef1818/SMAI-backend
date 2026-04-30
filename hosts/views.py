from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.utils import timezone
from django.db.models import Count
from django.contrib.auth import get_user_model
from .models import Host
from .serializers import HostSerializer, HostRegistrationSerializer, HeartbeatSerializer
import logging

logger = logging.getLogger(__name__)


User = get_user_model()


class HostRegisterView(APIView):

    permission_classes = [AllowAny]

    def post(self,request):
        logger.info(f"[HOST REGISTER] Incoming request from {request.META.get('REMOTE_ADDR')}")
        logger.info(f"[HOST REGISTER] Headers: {dict(request.headers)}")
        logger.info(f"[HOST REGISTER] Body: {request.data}")
        serializer = HostRegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            logger.warning(f"[HOST REGISTER] Validation failed: {serializer.errors}")

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        mac = serializer.validated_data['mac_address']

        host , created = Host.objects.update_or_create(
            mac_address=mac,
            defaults={
                'hostname': serializer.validated_data['hostname'],
                'ip_address': serializer.validated_data['ip_address'],
                'os': serializer.validated_data['os'],
                'status':'online',
                'last_seen':timezone.now(),
            }
        )

        logger.info(f"[HOST REGISTER] Host {host.hostname} ({'created' if created else 'updated'}) with API key {host.api_key[:8]}...")
        
        return Response({
                    'host_id': str(host.id),
                    'api_key': str(host.api_key),
                    'created': created
            },
            status = status.HTTP_201_CREATED if created else status.HTTP_200_OK
        )
    
class HeartBeat(APIView):
    permission_classes = [AllowAny]

    def post(self,request):

        serializer = HeartbeatSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            host = Host.objects.get(mac_address=serializer.validated_data['mac_address'])
            host.last_seen = timezone.now()
            host.status = 'online'
            host.save()
            return Response({'status': 'ok'})
        except Host.DoesNotExist:
            return Response({'error': 'Host not found.'}, status=status.HTTP_404_NOT_FOUND)
        
class HostListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        
        if request.user.is_admin:
            hosts = Host.objects.all()
        elif request.user.is_leader:
            hosts = Host.objects.filter(
                group__leader=request.user
            )
        else:
            return Response({'error': 'Only admins can list hosts.'}, status=status.HTTP_403_FORBIDDEN)
        
        return Response(HostSerializer(hosts, many=True).data ,status=status.HTTP_200_OK)
    

class HostDetailsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            host = Host.objects.get(pk=pk)
        except Host.DoesNotExist:
            return Response({'error': 'Host not found.'},
                             status=status.HTTP_404_NOT_FOUND)
        
        if request.user.is_employee and request.user.host != host:
            return Response({'error': 'You are not authorized to view this host.'},
                             status=status.HTTP_403_FORBIDDEN)
        
        if request.user.is_group_leader and (not host.group or host.group.leader != request.user):
            return Response({'error': 'You are not authorized to view this host.'},
                             status=status.HTTP_403_FORBIDDEN)
        
        serializer = HostSerializer(host)
        return Response(serializer.data, status=status.HTTP_200_OK)


class HostAgentStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.is_admin:
            hosts = Host.objects.all()
        elif request.user.is_group_leader:
            hosts = Host.objects.filter(group__leader=request.user)
        else:
            hosts = Host.objects.filter(pk=request.user.host_id)

        status_counts = (
            hosts.values('status')
                 .annotate(count=Count('status'))
                 .order_by('-count')
        )

        return Response({
            'total_hosts': hosts.count(),
            'status_counts': status_counts,
            'hosts': HostSerializer(hosts, many=True).data,
        }, status=status.HTTP_200_OK)
    