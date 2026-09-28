from crum import get_current_user
from django import forms
from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _

from dojo.authorization.authorization import user_has_configuration_permission, user_is_superuser_or_global_owner
from dojo.models import Dojo_User, User, UserContactInfo
from dojo.utils import get_password_requirements_string, get_system_setting


class DojoUserForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not get_current_user().is_superuser and not get_system_setting("enable_user_profile_editable"):
            for field in self.fields:
                self.fields[field].disabled = True

    class Meta:
        model = Dojo_User
        exclude = ["password", "last_login", "is_superuser", "groups",
                   "username", "is_staff", "is_active", "date_joined",
                   "user_permissions"]


class AddDojoUserForm(forms.ModelForm):
    email = forms.EmailField(required=True)
    password = forms.CharField(widget=forms.PasswordInput,
        required=settings.REQUIRE_PASSWORD_ON_USER,
        validators=[validate_password],
        help_text=_(""))

    class Meta:
        model = Dojo_User
        fields = ["username", "password", "first_name", "last_name", "email", "is_active", "is_staff", "is_superuser"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        current_user = get_current_user()
        if not current_user.is_superuser:
            self.fields["is_staff"].disabled = True
            self.fields["is_superuser"].disabled = True
        self.fields["password"].help_text = get_password_requirements_string()


class EditDojoUserForm(forms.ModelForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = Dojo_User
        fields = ["username", "first_name", "last_name", "email", "is_active", "is_staff", "is_superuser"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        current_user = get_current_user()
        if not current_user.is_superuser:
            self.fields["is_staff"].disabled = True
            self.fields["is_superuser"].disabled = True

    def clean(self):
        cleaned_data = super().clean()
        # Only a superuser may change the username or email of an account other
        # than their own: rewriting a victim's email and triggering a password
        # reset is an account-takeover vector. Mirrors UserSerializer.validate()
        # on the API path.
        current_user = get_current_user()
        if (
            current_user is not None
            and not current_user.is_superuser
            and self.instance.pk is not None
            and self.instance.pk != current_user.pk
        ):
            for identity_field in ("username", "email"):
                if identity_field in cleaned_data and cleaned_data[identity_field] != getattr(self.instance, identity_field):
                    self.add_error(
                        identity_field,
                        _("Only superusers are allowed to change the username or email of another user."),
                    )
        return cleaned_data


class DeleteUserForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = User
        fields = ["id"]


class UserContactInfoForm(forms.ModelForm):
    language = forms.ChoiceField(
        required=False,
        choices=[("", _("Use instance default")), *settings.LANGUAGES],
        label=_("Language"),
        help_text=_("Preferred language for the DefectDojo UI."),
    )
    reset_api_token = forms.BooleanField(
        required=False,
        label=_("Reset API token"),
        help_text=_("Upon saving, a new token will be generated and a notification of category 'Other' is triggered."),
    )

    class Meta:
        model = UserContactInfo
        exclude = ["user", "slack_user_id"]
        # Swap order: password_last_reset before token_last_reset
        field_order = [
            "title", "phone_number", "cell_number", "twitter_username", "github_username",
            "slack_username", "block_execution", "deduplication_execution_mode", "force_password_reset", "reset_api_token",
            "password_last_reset", "token_last_reset",
        ]

    def __init__(self, *args, **kwargs):
        user = kwargs.pop("user", None)
        super().__init__(*args, **kwargs)
        # Make timestamp fields readonly.
        # NOTE: `disabled=True` is enforced server-side by Django forms: posted values for disabled fields
        # are ignored during binding/cleaning, so these timestamps cannot be modified via this form.
        if "password_last_reset" in self.fields:
            self.fields["password_last_reset"].disabled = True
        if "token_last_reset" in self.fields:
            self.fields["token_last_reset"].disabled = True
        # token_expiry is a security control, not a preference: this form is reachable by any user
        # for their own profile, and Meta.exclude only drops "user"/"slack_user_id", so leaving it
        # enabled would let a user clear or extend their own token expiry. Setting it is reserved
        # for superusers via /api/v2/user_contact_infos/.
        if "token_expiry" in self.fields:
            self.fields["token_expiry"].disabled = True
        # Do not expose force password reset if the current user does not have a password to reset
        if user is not None:
            if not user.has_usable_password():
                self.fields["force_password_reset"].disabled = True
                self.fields["force_password_reset"].help_text = "This user is authorized through SSO, and does not have a password to reset"
        # Determine some other settings based on the current user
        current_user = get_current_user()
        if not current_user.is_superuser:
            if not user_has_configuration_permission(current_user, "auth.change_user") and \
               not user_has_configuration_permission(current_user, "auth.add_user"):
                self.fields.pop("force_password_reset", None)
            if not get_system_setting("enable_user_profile_editable"):
                for field in self.fields:
                    self.fields[field].disabled = True

        # Only show reset_api_token to superusers or global owners, and only if API tokens are enabled
        if not settings.API_TOKENS_ENABLED or not user_is_superuser_or_global_owner(current_user):
            self.fields.pop("reset_api_token", None)
