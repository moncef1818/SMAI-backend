from rest_framework import serializers
from .models import Incident


class IncidentSerializer(serializers.ModelSerializer):
    host_id = serializers.UUIDField(source='host.id', read_only=True)
    host_hostname = serializers.CharField(source='host.hostname', read_only=True)
    event_id = serializers.UUIDField(source='event.event_id', read_only=True, allow_null=True)
    group_name = serializers.CharField(source='host.group.name', read_only=True, allow_null=True)

    class Meta:
        model = Incident
        fields = [
            'incident_id',
            'host_id',
            'host_hostname',
            'group_name',
            'threat_type',
            'threat_source',
            'severity',
            'mitre',
            'ai_summary',
            'event_id',
            'created_at',
        ]
        read_only_fields = fields
