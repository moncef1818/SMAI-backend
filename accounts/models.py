from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    ROLES_CHOICES = [
        ('admin', 'Admin'),
        ('leader', 'Group Leader'),
        ('employee', 'Employeee')
    ]

    role = models.CharField(
        max_length=10,
        choices=ROLES_CHOICES,
        default='employee'
        )

    host = models.OneToOneField(
        'hosts.Host',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='user'
    )

    def __str__(self):
        return f'({self.username}:{self.role})'
    
    @property
    def is_admin(self):
        return self.role == 'admin'
    
    @property
    def is_leader(self):
        return self.role == 'leader'
    
    @property
    def is_employee(self):
        return self.role == 'employee'
    



# Create your models here.
