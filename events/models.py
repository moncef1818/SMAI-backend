from django.db import models
import uuid

class Event(models.Model):

    SOURCE_CHOICES = [
        ('agent', 'Agent'),
        ('browser', 'Browser Extension'),
    ]

    LOG_SOURCE_CHOICES = [
        ('NetworkMonitor', 'Network Monitor'),
        ('FileIntegrityMonitor', 'File Integrity Monitor'),
        ('ProcessMonitor', 'Process Monitor'),
    ]

    event_id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)
    source_type = models.CharField(max_length=50, choices=SOURCE_CHOICES, default='unknown')
    log_source = models.CharField(max_length=100, choices=LOG_SOURCE_CHOICES, default='unknown')
    host = models.ForeignKey(
        'hosts.Host',
        on_delete=models.CASCADE,
        related_name='events'
    )
    event_type = models.CharField(max_length=100)
    payload = models.JSONField()
    received_at = models.DateTimeField(auto_now_add=True)
    processed = models.BooleanField(default=False)

    class Meta:
        ordering = ['-received_at']

    def __str__(self):
        return f"[{self.log_source}] {self.event_type} from {self.host} @ {self.received_at}"
