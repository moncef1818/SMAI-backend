from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model
from .models import Group
from .serializers import GroupSerializer, AssignLeaderSerializer, AssignHostSerializer
from hosts.serializers import HostSerializer
from hosts.models import Host
from accounts.permissions import IsUser

User = get_user_model()

class GroupListView(APIView):
    permission_classes = [IsAuthenticated, IsUser]

    def get(self, request):
        
        if request.user.is_admin:
            groups = Group.objects.all()
        elif request.user.is_group_leader:
            groups = Group.objects.filter(
                leader=request.user
            )
        else:
            return Response({'error': 'Only admins can list groups.'}, status=status.HTTP_403_FORBIDDEN)
        
        return Response(GroupSerializer(groups, many=True).data ,status=status.HTTP_200_OK)
    
class GroupCreateView(APIView):
    permission_classes = [IsAuthenticated, IsUser]

    def post(self, request):

        if not request.user.is_admin:
            return Response({'error': 'Only admins can create groups.'},
                             status=status.HTTP_403_FORBIDDEN)
        
        serializer = GroupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class AssignHostToGroupView(APIView):
    permission_classes = [IsAuthenticated, IsUser]

    def post(self, request,pk):
        if not request.user.is_admin:
            return Response({'error': 'Only admins can assign hosts to groups.'},
                             status=status.HTTP_403_FORBIDDEN)

        serialzer = AssignHostSerializer(data=request.data)
        if not serialzer.is_valid():
            return Response(serialzer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            group = Group.objects.get(pk=pk)
            host = Host.objects.get(pk=serialzer.validated_data['host_id'])
            host.group = group
            host.save()
            return Response(HostSerializer(host).data , status=status.HTTP_200_OK)
        except Group.DoesNotExist:
            return Response({'error': 'Group not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Host.DoesNotExist:
            return Response({'error': 'Host not found.'}, status=status.HTTP_404_NOT_FOUND)

class AssignLeaderToGroupView(APIView):
    permission_classes = [IsAuthenticated, IsUser]
    def post(self, request,pk):
        if not request.user.is_admin:
            return Response({'error': 'Only admins can assign leaders to groups.'},
                            status=status.HTTP_403_FORBIDDEN)
        
        serializer = AssignLeaderSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            group = Group.objects.get(pk=pk)
            leader =  User.objects.get(pk=serializer.validated_data['leader_id'])

            group.leader = leader
            group.save()

            leader.role = 'leader'
            leader.save()

            return Response(GroupSerializer(group).data , status=status.HTTP_200_OK)
        except Group.DoesNotExist:
            return Response({'error': 'Group not found.'}, status=status.HTTP_404_NOT_FOUND)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
                             