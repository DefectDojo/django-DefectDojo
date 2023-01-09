from django.db import models
from django.utils.translation import gettext as _


class Sonarqube_Issue(models.Model):
    key = models.CharField(max_length=30, unique=True, help_text=_("SonarQube issue key"))
    status = models.CharField(max_length=20, help_text=_("SonarQube issue status"))
    type = models.CharField(max_length=20, help_text=_("SonarQube issue type"))

    def __str__(self):
        return self.key


class Sonarqube_Issue_Transition(models.Model):
    sonarqube_issue = models.ForeignKey(Sonarqube_Issue, on_delete=models.CASCADE, db_index=True)
    created = models.DateTimeField(auto_now_add=True, null=False)
    finding_status = models.CharField(max_length=100)
    sonarqube_status = models.CharField(max_length=50)
    transitions = models.CharField(max_length=100)

    class Meta:
        ordering = ('-created', )
