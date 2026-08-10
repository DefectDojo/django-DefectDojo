from django.db import models
from django.urls import reverse


class Development_Environment(models.Model):
    name = models.CharField(max_length=200)

    def __str__(self):
        return self.name

    def get_breadcrumbs(self):
        return [{"title": str(self),
                 "url": reverse("edit_dev_env", args=(self.id,))}]
