from django.urls import path
from .views import GroupListView , GroupCreateView ,AssignHostToGroupView ,AssignLeaderToGroupView

urlpatterns = [
    path('list/', GroupListView.as_view(), name='group-list'),
    path('create/', GroupCreateView.as_view(), name='group-create'),
    path('assign-host/<uuid:pk>/', AssignHostToGroupView.as_view(), name='assign-host'),
    path('assign-leader/<uuid:pk>/', AssignLeaderToGroupView.as_view(), name='assign-leader'),
]