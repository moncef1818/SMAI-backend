from django.db.models import Count
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import Incident
from .serializers import IncidentSerializer
from accounts.permissions import IsUser


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
    permission_classes = [IsAuthenticated, IsUser]

    def get(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = IncidentSerializer(queryset.order_by('-created_at'), many=True)
        return Response(serializer.data)


class IncidentSummaryView(IncidentScopeMixin, APIView):
    permission_classes = [IsAuthenticated, IsUser]

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
    permission_classes = [IsAuthenticated, IsUser]

    def get(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        queryset = queryset.filter(severity__in=['high', 'critical'])
        serializer = IncidentSerializer(queryset.order_by('-created_at'), many=True)
        return Response(serializer.data)


class NetworkIncidentListView(IncidentScopeMixin, APIView):
    permission_classes = [IsAuthenticated, IsUser]

    def get(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        queryset = queryset.filter(event__log_source='NetworkMonitor')
        serializer = IncidentSerializer(queryset.order_by('-created_at'), many=True)
        return Response(serializer.data)


class NetworkSummaryView(IncidentScopeMixin, APIView):
    permission_classes = [IsAuthenticated, IsUser]

    def get(self, request):
        queryset = self.filter_queryset(self.get_queryset())

        # Network-specific metrics
        total_incidents = queryset.count()
        network_incidents = queryset.filter(event__log_source='NetworkMonitor').count()
        critical_incidents = queryset.filter(severity='critical').count()
        high_incidents = queryset.filter(severity='high').count()

        # Calculate network score (0-100, higher is better)
        # Base score of 100, reduce based on incidents
        base_score = 100
        score_penalty = min(total_incidents * 2, 80)  # Max penalty of 80 points
        network_score = max(0, base_score - score_penalty)

        # Threat vector percentages (simulated based on incident data)
        # If no network incidents, use general incident data with lower weights
        if network_incidents == 0:
            anomaly_score = min(100, total_incidents * 5 + critical_incidents * 10)
            latency_score = min(100, high_incidents * 8 + total_incidents * 3)
            throughput_score = min(100, critical_incidents * 15 + high_incidents * 5)
        else:
            anomaly_score = min(100, network_incidents * 10 + critical_incidents * 20)
            latency_score = min(100, high_incidents * 15 + total_incidents * 5)
            throughput_score = min(100, critical_incidents * 25 + network_incidents * 8)

        # Network flow stats (simulated)
        active_flows = max(50, 142 - total_incidents * 2)
        bandwidth = max(5.0, 14.2 - total_incidents * 0.1)

        return Response({
            'network_score': network_score,
            'threat_vectors': {
                'anomaly_z': anomaly_score,
                'latency_iat': latency_score,
                'throughput': throughput_score,
            },
            'network_stats': {
                'active_flows': active_flows,
                'bandwidth_bpps': round(bandwidth, 1),
            },
            'incident_counts': {
                'total': total_incidents,
                'network': network_incidents,
                'critical': critical_incidents,
                'high': high_incidents,
            }
        })
