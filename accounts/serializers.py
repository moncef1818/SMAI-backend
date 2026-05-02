from rest_framework import serializers
from django.contrib.auth import get_user_model
from hosts.models import Host

User = get_user_model()


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True, min_length=8)
    mac_address = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm', 'mac_address']

    def validate(self, data):
        if data['password'] != data.pop('password_confirm'):
            raise serializers.ValidationError({"password": "Passwords do not match."})
        
        mac_address = data.pop('mac_address')
        try:
            host = Host.objects.get(mac_address=mac_address)
            data['host'] = host
        except Host.DoesNotExist:
            raise serializers.ValidationError({"mac_address": "Host not found with this MAC address."})
        
        return data

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            host=validated_data['host'],
            role='employee'
        )
        return user
    
    
class UserSerializer(serializers.ModelSerializer):
    host_hostname = serializers.CharField(source='host.hostname', read_only=True)
    group_name = serializers.CharField(source='host.group.name', read_only=True, allow_null=True)
    group_id = serializers.IntegerField(source='host.group.id', read_only=True, allow_null=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'role', 
                  'host', 'host_hostname', 'group_id', 'group_name', 'is_staff']
        read_only_fields = ['id', 'is_staff']


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)


class UserDetailSerializer(serializers.ModelSerializer):
    host_hostname = serializers.CharField(source='host.hostname', read_only=True)
    group_name = serializers.CharField(source='host.group.name', read_only=True, allow_null=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'role', 
                  'host_hostname', 'group_name', 'date_joined']
        read_only_fields = ['id', 'date_joined', 'role']


class AssignUserToGroupView(serializers.Serializer):
    """Admin assigns a host to a group (which updates all users of that host)."""
    host_id = serializers.CharField()
    group_id = serializers.UUIDField()


class ElevateUserSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    new_role = serializers.ChoiceField(choices=['leader', 'admin'])

