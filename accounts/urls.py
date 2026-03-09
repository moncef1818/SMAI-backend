from django.urls import path
from .views import RegisterView ,MeView ,ChangeRoleView ,ListUsersView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('me/', MeView.as_view(), name='me'),
    path('change-role/', ChangeRoleView.as_view(), name='change-role'),
    path('users/', ListUsersView.as_view(), name='list-users'),
]