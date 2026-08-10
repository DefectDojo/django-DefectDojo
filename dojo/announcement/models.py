from django.db import models
from django.utils.translation import gettext as _

ANNOUNCEMENT_STYLE_CHOICES = (
    ("info", "Info"),
    ("success", "Success"),
    ("warning", "Warning"),
    ("danger", "Danger"),
)


class Announcement(models.Model):
    message = models.CharField(max_length=500,
                                help_text=_("This dismissable message will be displayed on all pages for authenticated users. It can contain basic html tags, for example <a href='https://www.fred.com' style='color: #337ab7;' target='_blank'>https://example.com</a>"),
                                default="")
    style = models.CharField(max_length=64, choices=ANNOUNCEMENT_STYLE_CHOICES, default="info",
                            help_text=_("The style of banner to display. (info, success, warning, danger)"))
    dismissable = models.BooleanField(default=False,
                                      null=False,
                                      blank=True,
                                      verbose_name=_("Dismissable?"),
                                      help_text=_("Ticking this box allows users to dismiss the current announcement"),
                                      )


class UserAnnouncement(models.Model):
    announcement = models.ForeignKey("dojo.Announcement", null=True, editable=False, on_delete=models.CASCADE, related_name="user_announcement")
    user = models.ForeignKey("dojo.Dojo_User", null=True, editable=False, on_delete=models.CASCADE)
