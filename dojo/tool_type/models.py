from django.db import models


class Tool_Type(models.Model):
    name = models.CharField(max_length=200)
    description = models.CharField(max_length=2000, null=True, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name
