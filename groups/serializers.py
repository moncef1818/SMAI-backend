from .models import Group
from rest_framework import serializers
from hosts.serializers import HostSerializer
from django.contrib.auth import get_user_model

User = get_user_model()

class GroupSerializer(serializers.ModelSerializer):
    hosts = HostSerializer(many=True, read_only=True)
    leader_username = serializers.ReadOnlyField(source='leader.username' ,read_only=True)

    class Meta:
        model = Group
        fields = ['id', 'name', 'leader', 'leader_username', 'hosts', 'created_at']
        read_only_fields = ['id', 'created_at']

class AssignHostSerializer(serializers.Serializer):
    host_id = serializers.UUIDField()

class AssignLeaderSerializer(serializers.Serializer):
    user_id = serializers.UUIDField()