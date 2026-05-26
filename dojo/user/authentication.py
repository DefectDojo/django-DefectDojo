from datetime import timedelta

from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied, ValidationError

from dojo.authorization.authorization import user_is_superuser_or_global_owner
from dojo.models import Dojo_User, UserContactInfo
from dojo.notifications.helper import create_notification


class ExpiringTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        user, token = super().authenticate_credentials(key)
        uci = getattr(user, "usercontactinfo", None)
        if uci and uci.token_expiry and uci.token_expiry < timezone.now():
            raise AuthenticationFailed("Token has expired.")
        return user, token


def reset_token_for_user(*, acting_user: Dojo_User, target_user: Dojo_User, allow_self_reset: bool = False) -> None:
    if not settings.API_TOKENS_ENABLED:
        msg = "API tokens are disabled."
        raise PermissionDenied(msg)

    if acting_user is None or getattr(acting_user, "is_anonymous", False):
        msg = "Authentication required."
        raise PermissionDenied(msg)

    if acting_user == target_user and not allow_self_reset:
        msg = "Resetting your own API token via this endpoint is not allowed."
        raise ValidationError(msg)

    # Only check permissions if not self-reset (self-reset is always allowed when allow_self_reset=True)
    if acting_user != target_user and not user_is_superuser_or_global_owner(acting_user):
        msg = "Insufficient permissions to reset API tokens."
        raise PermissionDenied(msg)

    # Rotate token: delete existing token (if any), then create a new one.
    Token.objects.filter(user=target_user).delete()
    Token.objects.create(user=target_user)

    expiry_days = getattr(settings, "API_TOKEN_DEFAULT_EXPIRY_DAYS", 0)
    uci, _ = UserContactInfo.objects.get_or_create(user=target_user)
    uci.token_last_reset = timezone.now()
    uci.token_expiry = timezone.now() + timedelta(days=expiry_days) if expiry_days else None
    uci.save(update_fields=["token_last_reset", "token_expiry"])

    # Send notification to the target user
    if acting_user == target_user:
        # Self-reset notification
        description = f"A new API token has been generated for user {target_user.username}."
        requested_by = None
    else:
        # Admin reset notification
        description = (
            f"Your API token has been reset by {acting_user.get_full_name() or acting_user.username}. "
            f"Please retrieve the new API token via the UI to keep using the API."
        )
        requested_by = acting_user

    create_notification(
        event="other",
        title="API Token Reset",
        description=description,
        recipients=[target_user],
        url=reverse("api_v2_key"),
        requested_by=requested_by,
        icon="key",
    )
