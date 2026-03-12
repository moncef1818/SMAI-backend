# events/urls.py
from django.urls import path
from .views import EventIngestView

urlpatterns = [
    path('', EventIngestView.as_view(), name='event-ingest'),
]