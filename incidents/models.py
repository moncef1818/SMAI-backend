from django.db import models
import uuid

class Incident(models.Model):

    THREAT_SOURCE_CHOICES = [
        ('rule', 'Rule-based Detection'),
        ('ml', 'Machine Learning Detection'),
    ]

    SEVERITY_CHOICES = [
        ('info', 'Info'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    incident_id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    host = models.ForeignKey(
        "hosts.Host",
        on_delete=models.CASCADE,
        related_name="incidents",
    )
    event = models.ForeignKey(
        "events.Event",
        on_delete=models.CASCADE,
        related_name="incidents",
        null= True,
        blank=True,
    )
    threat_type = models.CharField(max_length=100, help_text="rule_id or ML model name")
    threat_source = models.CharField(max_length=20, choices=THREAT_SOURCE_CHOICES)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    mitre = models.CharField(max_length=20, null=True, blank=True)
    ai_summary = models.JSONField(default=dict, help_text="Triggering fields or ML confidence scores")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.severity.upper()}] {self.threat_type} on {self.host} @ {self.created_at}"