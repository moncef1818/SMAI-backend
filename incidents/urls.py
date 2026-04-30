from django.urls import path
from .views import IncidentListView, IncidentSummaryView, IncidentAlertsView, NetworkIncidentListView

urlpatterns = [
    path('', IncidentListView.as_view(), name='incident-list'),
    path('summary/', IncidentSummaryView.as_view(), name='incident-summary'),
    path('alerts/', IncidentAlertsView.as_view(), name='incident-alerts'),
    path('network/', NetworkIncidentListView.as_view(), name='network-incident-list'),
]
