from django.db import models
import secrets
import uuid


# Host model for regestring hosts informations
# initiated by the Agents (Belkacem) after installing the agents using an API call
class Host(models.Model):

    STATUS_CHOICES = [
        ('online', 'Online'),
        ('offline', 'Offline'),
        ('warning', 'Warning'),
        ('critical', 'Critical'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    hostname = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()
    mac_address = models.CharField(max_length=17,unique=True)
    os = models.CharField(max_length=100)
    group = models.ForeignKey('groups.Group',
                                on_delete=models.SET_NULL,
                                null=True, blank=True,
                                related_name='host'
                                )
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='online')
    last_seen = models.DateTimeField(null=True, blank=True)  
    registered_at = models.DateTimeField(auto_now_add=True)

    api_key = models.CharField(max_length=64, unique=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.api_key:
            self.api_key = secrets.token_hex(32)
        super().save(*args, **kwargs)
        
    def __str__(self):
        return str(self.hostname + " (" + self.ip_address + ")" + self.mac_address + self.os )
    
    @property
    def is_authenticated(self):
        return True

    @property
    def threat_score(self):
        incidents = self.incidents.all().order_by('-created_at')[:10]
        if not incidents:
            return 0
        
        score = 0
        for i in incidents:
            if i.severity == 'critical':
                score += 15
            elif i.severity == 'high':
                score += 10
            elif i.severity == 'medium':
                score += 5
            elif i.severity == 'low':
                score += 2
        return min(100, score)