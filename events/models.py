from django.db import models
import uuid

class Event(models.Model):

    SOURCE_CHOICES = [
        ('agent', 'Agent'),
        ('browser', 'Browser Extension'),
    ]

    LOG_SOURCE_CHOICES = [


        ('NetworkMonitor', 'Network Monitor'),
        ('FileMonitor', 'File Monitor'),
        ('ProcessMonitor', 'Process Monitor'),
        ('AuthMonitor', 'Authentication Monitor'),
        ('UsbMonitor', 'USB Monitor'),
        ('RegistryMonitor', 'Registry Monitor'),

        ('BrowserExtension', 'Browser Extension'),
        
    ]

    DETECTION_SOURCE = [
        ("rule", "Rule-based"),
        ("ml", "ML model"),
        ("both", "Rule + ML"),
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
    rule_triggered = models.BooleanField(default=False)
    detection_source = models.CharField(
        max_length=10,
        choices=DETECTION_SOURCE,
        null=True,
        blank=True,
        help_text=(
            "Populated once the event has been evaluated. "
            "Null until processing is complete."
        ),
    )

    class Meta:
        ordering = ['-received_at']

    def __str__(self):
        return f"[{self.log_source}] {self.event_type} from {self.host} @ {self.received_at}"
