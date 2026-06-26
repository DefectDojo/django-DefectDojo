from django.contrib.auth import get_user_model
from django.core.validators import RegexValidator
from django.db import models
from django.utils.translation import gettext as _

User = get_user_model()


# proxy class for convenience and UI
class Dojo_User(User):
    class Meta:
        proxy = True
        ordering = ["first_name"]

    def get_full_name(self):
        return Dojo_User.generate_full_name(self)

    def __str__(self):
        return self.get_full_name()

    @staticmethod
    def wants_block_execution(user):
        # this return False if there is no user, i.e. in celery processes, unittests, etc.
        return hasattr(user, "usercontactinfo") and user.usercontactinfo.block_execution

    @staticmethod
    def force_password_reset(user):
        return hasattr(user, "usercontactinfo") and user.usercontactinfo.force_password_reset

    def disable_force_password_reset(self):
        if hasattr(self, "usercontactinfo"):
            self.usercontactinfo.force_password_reset = False
            self.usercontactinfo.save()

    def enable_force_password_reset(self):
        if hasattr(self, "usercontactinfo"):
            self.usercontactinfo.force_password_reset = True
            self.usercontactinfo.save()

    @staticmethod
    def generate_full_name(user):
        """Returns the first_name plus the last_name, with a space in between."""
        full_name = f"{user.first_name} {user.last_name} ({user.username})"
        return full_name.strip()


class UserContactInfo(models.Model):
    user = models.OneToOneField("dojo.Dojo_User", on_delete=models.CASCADE)
    title = models.CharField(blank=True, null=True, max_length=150)
    phone_regex = RegexValidator(regex=r"^\+?1?\d{9,15}$",
                                 message=_("Phone number must be entered in the format: '+999999999'. "
                                         "Up to 15 digits allowed."))
    phone_number = models.CharField(validators=[phone_regex], blank=True,
                                    max_length=15,
                                    help_text=_("Phone number must be entered in the format: '+999999999'. "
                                              "Up to 15 digits allowed."))
    cell_number = models.CharField(validators=[phone_regex], blank=True,
                                   max_length=15,
                                   help_text=_("Phone number must be entered in the format: '+999999999'. "
                                             "Up to 15 digits allowed."))
    twitter_username = models.CharField(blank=True, null=True, max_length=150)
    github_username = models.CharField(blank=True, null=True, max_length=150)
    slack_username = models.CharField(blank=True, null=True, max_length=150, help_text=_("Email address associated with your slack account"), verbose_name=_("Slack Email Address"))
    slack_user_id = models.CharField(blank=True, null=True, max_length=25)
    block_execution = models.BooleanField(default=False, help_text=_("Instead of async deduping a finding the findings will be deduped synchronously and will 'block' the user until completion."))
    force_password_reset = models.BooleanField(default=False, help_text=_("Forces this user to reset their password on next login."))
    ui_use_tailwind = models.BooleanField(default=False, verbose_name=_("Use new UI (beta)"), help_text=_("Opt in to the new Tailwind-based UI. Leave off for the classic UI."))
    token_last_reset = models.DateTimeField(null=True, blank=True, help_text=_("Timestamp of the most recent API token reset for this user."))
    password_last_reset = models.DateTimeField(null=True, blank=True, help_text=_("Timestamp of the most recent password reset for this user."))
    # Extensible per-user UI state: dismissed banners, "seen"/"don't show again"
    # flags, and similar small ephemeral preferences. Store new flags of this kind
    # as keys here instead of adding a dedicated column per flag (avoids a migration
    # and a schema column for every minor toggle). Not for queryable/behavioral data.
    user_state_details = models.JSONField(default=dict, blank=True, editable=False, help_text=_("Extensible per-user UI state (dismissed banners, 'don't show again' flags, ...)."))


class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    team = models.CharField(max_length=100)
    is_admin = models.BooleanField(default=False)
    is_globally_read_only = models.BooleanField(default=False)
    updated = models.DateTimeField(auto_now=True)
