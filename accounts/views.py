from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import get_user_model
from .serializers import UserSerializer, RegisterSerializer, ChangeRoleSerializer

User = get_user_model()

class RegisterView(APIView):

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class MeView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

class ChangeRoleView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self,request):
        if not request.user.is_admin:
            return{
            {'error': 'Only admins can change roles.'},
             Response(status=status.HTTP_403_FORBIDDEN)
        }

        serializer = ChangeRoleSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = User.objects.get(id=serializer.data['user_id'])
                user.role = serializer.validated_data['role']
                user.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class ListUsersView(APIView):
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        if request.user.is_admin:
            users = User.objects.all()
        elif request.user.is_leader:
            users = User.objects.filter(
                host__group__leader=request.user
            )
        else:
            return Response({'error': 'Only admins can list users.'}, status=status.HTTP_403_FORBIDDEN)
        
        return Response(UserSerializer(users, many=True).data ,status=status.HTTP_200_OK)