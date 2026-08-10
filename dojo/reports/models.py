from django.db import models


class Report_Type(models.Model):
    name = models.CharField(max_length=255)
