from django.contrib.auth.models import AbstractUser
from django.db import models
from hosts.models import Host


class User(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('group_leader', 'Group Leader'),
        ('employee', 'Employee'),
    ]
    
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='employee')
    host = models.OneToOneField(
        Host,
        on_delete=models.CASCADE,
        related_name='user'
    )

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return f"{self.username} ({self.role})"

    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def is_group_leader(self):
        return self.role == 'group_leader'

    @property
    def is_employee(self):
        return self.role == 'employee'
    
    @property
    def group(self):
        """Access group through host relationship."""
        return self.host.group if self.host else None