from django.db import models
from django.utils.translation import gettext as _


class BannerConf(models.Model):
    banner_enable = models.BooleanField(default=False, null=True, blank=True)
    banner_message = models.CharField(max_length=500, help_text=_("This message will be displayed on the login page. It can contain basic html tags, for example <a href='https://www.fred.com' style='color: #337ab7;' target='_blank'>https://example.com</a>"), default="")
