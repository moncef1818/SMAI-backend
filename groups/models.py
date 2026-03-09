from django.db import models
import uuid

# Group model for hosts grouping (can be created only by admins)
class Group(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50)
    description = models.TextField()  
    leader = models.ForeignKey('accounts.User',
                                on_delete=models.SET_NULL,
                                null=True, blank=True,
                                related_name='leader'
                                )  
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.name) + ':' + str(self.leader)

# Create your models here.
