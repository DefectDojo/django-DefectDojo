from django.db import models


class Note_Type(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=200)
    is_single = models.BooleanField(default=False, null=False)
    is_active = models.BooleanField(default=True, null=False)
    is_mandatory = models.BooleanField(default=True, null=False)

    def __str__(self):
        return self.name
