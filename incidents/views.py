from django.db.models import Count
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Incident
from .serializers import IncidentSerializer


class IncidentScopeMixin:
    def get_queryset(self):
        user = self.request.user
        if user.is_admin:
            return Incident.objects.select_related('host', 'event').all()

        if user.is_group_leader:
            return Incident.objects.select_related('host', 'event').filter(host__group__leader=user)

        return Incident.objects.select_related('host', 'event').filter(host=user.host)

    def filter_queryset(self, queryset):
        params = self.request.query_params
        if severity := params.get('severity'):
            queryset = queryset.filter(severity=severity)
        if threat_source := params.get('threat_source'):
            queryset = queryset.filter(threat_source=threat_source)
        if host_id := params.get('host_id'):
            queryset = queryset.filter(host__id=host_id)
        if group_id := params.get('group_id'):
            queryset = queryset.filter(host__group__id=group_id)
        if log_source := params.get('log_source'):
            queryset = queryset.filter(event__log_source=log_source)
        return queryset


class IncidentListView(IncidentScopeMixin, APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = IncidentSerializer(queryset.order_by('-created_at'), many=True)
        return Response(serializer.data)


class IncidentSummaryView(IncidentScopeMixin, APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        severity_counts = list(
            queryset.values('severity')
                    .annotate(count=Count('severity'))
                    .order_by('-count')
        )
        source_counts = list(
            queryset.values('threat_source')
                    .annotate(count=Count('threat_source'))
                    .order_by('-count')
        )
        host_counts = list(
            queryset.values('host__hostname')
                    .annotate(count=Count('host'))
                    .order_by('-count')[:5]
        )
        network_total = queryset.filter(event__log_source='NetworkMonitor').count()
        return Response({
            'total_incidents': queryset.count(),
            'severity_counts': severity_counts,
            'threat_source_counts': source_counts,
            'top_hosts': host_counts,
            'network_incident_count': network_total,
        })


class IncidentAlertsView(IncidentScopeMixin, APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        queryset = queryset.filter(severity__in=['high', 'critical'])
        serializer = IncidentSerializer(queryset.order_by('-created_at'), many=True)
        return Response(serializer.data)


class NetworkIncidentListView(IncidentScopeMixin, APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        queryset = queryset.filter(event__log_source='NetworkMonitor')
        serializer = IncidentSerializer(queryset.order_by('-created_at'), many=True)
        return Response(serializer.data)
