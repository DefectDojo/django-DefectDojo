from django.db import models
from django.utils.translation import gettext as _


class GITHUB_Conf(models.Model):
    configuration_name = models.CharField(max_length=2000, help_text=_("Enter a name to give to this configuration"), default='')
    api_key = models.CharField(max_length=2000, help_text=_("Enter your Github API Key"), default='')

    def __str__(self):
        return self.configuration_name


class GITHUB_Issue(models.Model):
    issue_id = models.CharField(max_length=200)
    issue_url = models.URLField(max_length=2000, verbose_name=_('GitHub issue URL'))
    finding = models.OneToOneField('Finding', null=True, blank=True, on_delete=models.CASCADE)

    def __str__(self):
        return str(self.issue_id) + '| GitHub Issue URL: ' + str(self.issue_url)


class GITHUB_Clone(models.Model):
    github_id = models.CharField(max_length=200)
    github_clone_id = models.CharField(max_length=200)


class GITHUB_Details_Cache(models.Model):
    github_id = models.CharField(max_length=200)
    github_key = models.CharField(max_length=200)
    github_status = models.CharField(max_length=200)
    github_resolution = models.CharField(max_length=200)


class GITHUB_PKey(models.Model):
    product = models.ForeignKey('Product', on_delete=models.CASCADE)

    git_project = models.CharField(max_length=200, blank=True, verbose_name=_('Github project'), help_text=_('Specify your project location. (:user/:repo)'))
    git_conf = models.ForeignKey(GITHUB_Conf, verbose_name=_('Github Configuration'),
                                 null=True, blank=True, on_delete=models.CASCADE)
    git_push_notes = models.BooleanField(default=False, blank=True, help_text=_("Notes added to findings will be automatically added to the corresponding github issue"))

    def __str__(self):
        return self.product.name + " | " + self.git_project
