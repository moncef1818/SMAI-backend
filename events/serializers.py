from rest_framework import serializers
from .models import Event

class EventIngestSerializer(serializers.ModelSerializer):

    class Meta:
        model = Event
        fields = ['source_type', 'log_source', 'event_type', 'payload']