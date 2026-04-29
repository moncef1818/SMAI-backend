from rest_framework import serializers
from .models import Host
from django.contrib.auth import get_user_model

User = get_user_model()

class HostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Host
        fields = '__all__'

    read_only_fields = ['id', 'status', 'last_seen', 'registered_at']

class HostRegistrationSerializer(serializers.ModelSerializer):

    class Meta:
        model = Host
        fields = ['hostname', 'ip_address', 'mac_address', 'os']

class HeartbeatSerializer(serializers.Serializer):
    mac_address = serializers.CharField()

