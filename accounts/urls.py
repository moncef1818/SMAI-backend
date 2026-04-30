from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    RegisterView, LoginView, UserDetailView, LogoutView, ListUsersView,
    AssignHostToGroupView, ElevateUserView, ListGroupsView
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('user/', UserDetailView.as_view(), name='user_detail'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('me/', UserDetailView.as_view(), name='user_detail'),
    
    # Admin only
    path('users/', ListUsersView.as_view(), name='list_users'),
    path('hosts/assign-group/', AssignHostToGroupView.as_view(), name='assign_host_group'),
    path('users/elevate/', ElevateUserView.as_view(), name='elevate_user'),
    path('groups/', ListGroupsView.as_view(), name='list_groups'),
]