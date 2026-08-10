from datetime import timedelta

from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied, ValidationError

from dojo.authorization.authorization import user_is_superuser_or_global_owner
from dojo.models import Dojo_User, UserContactInfo
from dojo.notifications.helper import create_notification


def default_expiry_days() -> int:
    """Instance-wide token lifetime in days. 0 (the default) means tokens never expire."""
    try:
        days = int(getattr(settings, "API_TOKEN_DEFAULT_EXPIRY_DAYS", 0) or 0)
    except (TypeError, ValueError):
        return 0
    return max(days, 0)


def token_expires_at(token: Token):
    """
    Effective expiry for a token, or None when it never expires.

    An explicit ``token_expiry`` on the owner's contact info wins, so a superuser can pin or
    extend a single user. Otherwise the instance-wide default is measured from the token's own
    ``created`` timestamp.

    Deriving the default from ``created`` rather than stamping an expiry at creation time is
    deliberate: tokens are minted by three separate paths (``reset_token_for_user``, the lazy
    create on the UI key page, and DRF's ``api-token-auth`` endpoint), and a stamping approach
    silently grants an unexpiring token to anyone who uses a path that forgot to stamp.
    Computing it here covers every path, including any added later.
    """
    uci = getattr(token.user, "usercontactinfo", None)
    explicit = getattr(uci, "token_expiry", None)
    if explicit:
        return explicit
    days = default_expiry_days()
    if days and token.created:
        return token.created + timedelta(days=days)
    return None


def token_is_expired(token: Token) -> bool:
    expires_at = token_expires_at(token)
    return expires_at is not None and expires_at <= timezone.now()


class ExpiringTokenAuthentication(TokenAuthentication):

    """Token auth that additionally rejects tokens past their effective expiry."""

    def authenticate_credentials(self, key):
        user, token = super().authenticate_credentials(key)
        if token_is_expired(token):
            msg = "API token has expired."
            raise AuthenticationFailed(msg)
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

    # Clear any explicit expiry: it belonged to the token just replaced, and a past datetime
    # left behind would expire the new token immediately. The instance-wide default still
    # applies, measured from the new token's creation time.
    uci, _ = UserContactInfo.objects.get_or_create(user=target_user)
    uci.token_last_reset = timezone.now()
    uci.token_expiry = None
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
