from rest_framework.permissions import BasePermission
from django.contrib.auth import get_user_model

User = get_user_model()


class IsAdmin(BasePermission):
    """Only admin users can access."""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_admin


class IsGroupLeader(BasePermission):
    """Group leaders and admins can access."""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and (
            request.user.is_group_leader or request.user.is_admin
        )


class IsEmployee(BasePermission):
    """All authenticated users."""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated


class IsUser(BasePermission):
    """Only User instances can access (not Host API key auth)."""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and isinstance(request.user, User)