from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.views import TokenRefreshView
from django.contrib.auth import authenticate, get_user_model
from .serializers import (
    UserRegistrationSerializer, UserLoginSerializer, UserSerializer,
    AssignUserToGroupView, ElevateUserSerializer, UserDetailSerializer
)
from .permissions import IsAdmin

from hosts.models import Host
from groups.models import Group
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        logger.info(f"[REGISTER] New registration: {request.data.get('username')}")
        
        serializer = UserRegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        user = serializer.save()
        logger.info(f"[REGISTER] User {user.username} created, linked to host {user.host.hostname}")
        
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'user': UserSerializer(user).data,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        user = authenticate(
            username=serializer.validated_data['username'],
            password=serializer.validated_data['password']
        )
        
        if not user:
            logger.warning(f"[LOGIN] Failed for {serializer.validated_data['username']}")
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        
        logger.info(f"[LOGIN] User {user.username} logged in")
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'user': UserSerializer(user).data,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_200_OK)


class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserDetailSerializer(request.user)
        return Response(serializer.data)

    def patch(self, request):
        """Update user profile."""
        user = request.user
        allowed_fields = ['first_name', 'last_name', 'email']
        data = {k: v for k, v in request.data.items() if k in allowed_fields}
        
        serializer = UserDetailSerializer(user, data=data, partial=True)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        serializer.save()
        return Response(serializer.data)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return Response(
                {'refresh': 'This field is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError:
            return Response(
                {'detail': 'Token is invalid or expired.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except AttributeError:
            return Response(
                {
                    'success': True,
                    'message': 'Logout completed. Token blacklist support is not enabled.'
                },
                status=status.HTTP_200_OK
            )

        return Response({'success': True}, status=status.HTTP_200_OK)


class ListUsersView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        users = User.objects.select_related('host', 'host__group').all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)


class AssignHostToGroupView(APIView):
    """Admin: Assign a host to a group (affects all users of that host)."""
    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request):
        serializer = AssignUserToGroupView(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            host = Host.objects.get(id=serializer.validated_data['host_id'])
            group = Group.objects.get(id=serializer.validated_data['group_id'])
        except (Host.DoesNotExist, Group.DoesNotExist):
            return Response({'error': 'Host or Group not found'}, status=status.HTTP_404_NOT_FOUND)
        
        host.group = group
        host.save()
        
        logger.info(f"[ADMIN] Host {host.hostname} assigned to group {group.name}")
        
        return Response({
            'success': True,
            'message': f"Host {host.hostname} and its users assigned to {group.name}"
        }, status=status.HTTP_200_OK)


class ElevateUserView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request):
        serializer = ElevateUserSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(id=serializer.validated_data['user_id'])
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        old_role = user.role
        user.role = serializer.validated_data['new_role']
        user.save()
        
        logger.info(f"[ADMIN] User {user.username} role: {old_role} → {user.role}")
        
        return Response({
            'success': True,
            'user': UserSerializer(user).data
        })


class ListGroupsView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        from groups.serializers import GroupSerializer
        groups = Group.objects.all()
        serializer = GroupSerializer(groups, many=True)
        return Response(serializer.data)