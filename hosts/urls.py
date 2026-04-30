from django.urls import path
from .views import HostRegisterView, HostListView, HostDetailsView, HeartBeat, HostAgentStatusView

urlpatterns = [
    path('register/', HostRegisterView.as_view(), name='host-register'),
    path('list/', HostListView.as_view(), name='host-list'),
    path('details/<uuid:pk>/', HostDetailsView.as_view(), name='host-details'),
    path('agents/', HostAgentStatusView.as_view(), name='host-agents'),
    path('heartbeat/', HeartBeat.as_view(), name='heartbeat'),
]