from rest_framework import serializers
from .models import Host
from django.contrib.auth import get_user_model

User = get_user_model()

class HostSerializer(serializers.ModelSerializer):
    group_name = serializers.CharField(source='group.name', read_only=True)
    threat_score = serializers.SerializerMethodField()

    class Meta:
        model = Host
        fields = '__all__'

    read_only_fields = ['id', 'status', 'last_seen', 'registered_at']

    def get_threat_score(self, obj):
        return obj.threat_score

class HostRegistrationSerializer(serializers.ModelSerializer):

    class Meta:
        model = Host
        fields = ['hostname', 'ip_address', 'mac_address', 'os']

class HeartbeatSerializer(serializers.Serializer):
    mac_address = serializers.CharField()

