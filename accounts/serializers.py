from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role', 'host']
        read_only_fields = ['id', 'role', 'host']

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True , min_length=8)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def create(self, validated_data):
        return User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get('email',''),
            password=validated_data['password'],
            role='employee'
        )

class ChangeRoleSerializer(serializers.ModelSerializer):
    user_id = serializers.UUIDField()
    role = serializers.ChoiceField(choices=['admin', 'leader', 'employee'])

    
