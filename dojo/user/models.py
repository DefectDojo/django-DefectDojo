from django.contrib.auth import get_user_model
from django.core.validators import RegexValidator
from django.db import models
from django.utils.translation import gettext as _

User = get_user_model()


# Import post-processing execution modes.
# - ASYNC: post-processing (dedup, jira, grading, ...) runs in the background;
#   the API responds immediately (default, historical behavior).
# - ASYNC_WAIT: post-processing is dispatched to the background as usual, but the
#   request waits for the deduplication batches to finish before responding, so
#   notifications and the returned statistics reflect the deduplicated state.
# - SYNC: post-processing runs inline in the web process (legacy block_execution).
DEDUPLICATION_EXECUTION_MODE_ASYNC = "async"
DEDUPLICATION_EXECUTION_MODE_ASYNC_WAIT = "async_wait"
DEDUPLICATION_EXECUTION_MODE_SYNC = "sync"
DEDUPLICATION_EXECUTION_MODES = (
    DEDUPLICATION_EXECUTION_MODE_ASYNC,
    DEDUPLICATION_EXECUTION_MODE_ASYNC_WAIT,
    DEDUPLICATION_EXECUTION_MODE_SYNC,
)
DEDUPLICATION_EXECUTION_MODE_CHOICES = (
    (DEDUPLICATION_EXECUTION_MODE_ASYNC, _("Async (do not wait)")),
    (DEDUPLICATION_EXECUTION_MODE_ASYNC_WAIT, _("Async, wait for deduplication")),
    (DEDUPLICATION_EXECUTION_MODE_SYNC, _("Synchronous (block)")),
)


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
        # block_execution is the global "run all async tasks in the foreground" switch and
        # governs every dojo_dispatch_task/dojo_async_task call (notifications, jira, grading,
        # deduplication, ...). It is distinct from deduplication_execution_mode, which only
        # controls how import/reimport deduplication post-processing is dispatched/awaited.
        return hasattr(user, "usercontactinfo") and user.usercontactinfo.block_execution

    @staticmethod
    def resolve_deduplication_execution_mode(user, override=None):
        """
        Resolve the effective import/reimport deduplication execution mode.

        Priority: explicit request override > user profile deduplication_execution_mode >
        legacy block_execution (which forces everything sync) > default async.
        Returns one of DEDUPLICATION_EXECUTION_MODE_ASYNC / _ASYNC_WAIT / _SYNC.
        """
        if override in DEDUPLICATION_EXECUTION_MODES:
            return override
        info = getattr(user, "usercontactinfo", None)
        if info is not None:
            if info.deduplication_execution_mode in DEDUPLICATION_EXECUTION_MODES:
                return info.deduplication_execution_mode
            if info.block_execution:
                return DEDUPLICATION_EXECUTION_MODE_SYNC
        return DEDUPLICATION_EXECUTION_MODE_ASYNC

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
    deduplication_execution_mode = models.CharField(
        max_length=20,
        choices=DEDUPLICATION_EXECUTION_MODE_CHOICES,
        null=True,
        blank=True,
        help_text=_(
            "Controls how import/reimport deduplication post-processing is executed. "
            "'Async' dispatches it to the background and returns immediately (default). "
            "'Async, wait for deduplication' dispatches to the background but waits for "
            "deduplication to finish before responding, so notifications and statistics "
            "reflect the deduplicated state. 'Synchronous' runs the import deduplication "
            "inline. Can be overridden per request. Independent of block_execution, which "
            "forces all async tasks (notifications, jira, ...) to the foreground.",
        ),
    )
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
