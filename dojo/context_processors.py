import contextlib
import time

# import the settings file
from django.conf import settings
from django.contrib import messages

from dojo.labels import get_labels
from dojo.models import Alerts, System_Settings, UserAnnouncement


def globalize_vars(request):
    # return the value you want as a dictionnary. you may add multiple values in there.
    return {
        "SHOW_LOGIN_FORM": settings.SHOW_LOGIN_FORM,
        "FORGOT_PASSWORD": settings.FORGOT_PASSWORD,
        "FORGOT_USERNAME": settings.FORGOT_USERNAME,
        "CLASSIC_AUTH_ENABLED": settings.CLASSIC_AUTH_ENABLED,
        "OIDC_ENABLED": settings.OIDC_AUTH_ENABLED,
        "SOCIAL_AUTH_OIDC_LOGIN_BUTTON_TEXT": settings.SOCIAL_AUTH_OIDC_LOGIN_BUTTON_TEXT,
        "AUTH0_ENABLED": settings.AUTH0_OAUTH2_ENABLED,
        "GOOGLE_ENABLED": settings.GOOGLE_OAUTH_ENABLED,
        "OKTA_ENABLED": settings.OKTA_OAUTH_ENABLED,
        "GITLAB_ENABLED": settings.GITLAB_OAUTH2_ENABLED,
        "AZUREAD_TENANT_OAUTH2_ENABLED": settings.AZUREAD_TENANT_OAUTH2_ENABLED,
        "AZUREAD_TENANT_OAUTH2_GET_GROUPS": settings.AZUREAD_TENANT_OAUTH2_GET_GROUPS,
        "AZUREAD_TENANT_OAUTH2_GROUPS_FILTER": settings.AZUREAD_TENANT_OAUTH2_GROUPS_FILTER,
        "AZUREAD_TENANT_OAUTH2_CLEANUP_GROUPS": settings.AZUREAD_TENANT_OAUTH2_CLEANUP_GROUPS,
        "KEYCLOAK_ENABLED": settings.KEYCLOAK_OAUTH2_ENABLED,
        "SOCIAL_AUTH_KEYCLOAK_LOGIN_BUTTON_TEXT": settings.SOCIAL_AUTH_KEYCLOAK_LOGIN_BUTTON_TEXT,
        "GITHUB_ENTERPRISE_ENABLED": settings.GITHUB_ENTERPRISE_OAUTH2_ENABLED,
        "SAML2_ENABLED": settings.SAML2_ENABLED,
        "SAML2_LOGIN_BUTTON_TEXT": settings.SAML2_LOGIN_BUTTON_TEXT,
        "SAML2_LOGOUT_URL": settings.SAML2_LOGOUT_URL,
        "DOCUMENTATION_URL": settings.DOCUMENTATION_URL,
        "API_TOKENS_ENABLED": settings.API_TOKENS_ENABLED,
        "API_TOKEN_AUTH_ENDPOINT_ENABLED": settings.API_TOKEN_AUTH_ENDPOINT_ENABLED,
        "CREATE_CLOUD_BANNER": settings.CREATE_CLOUD_BANNER,
        # V3 Feature Flags
        "V3_FEATURE_LOCATIONS": settings.V3_FEATURE_LOCATIONS,
    }


def bind_system_settings(request):
    """Load system settings and display warning if there's a database error."""
    try:
        system_settings = System_Settings.objects.get()
        # Check if there was an error stored on the request (from middleware)
        if hasattr(request, "system_settings_error"):
            error_msg = request.system_settings_error
            messages.add_message(
                request,
                messages.WARNING,
                f"Warning: Unable to load system settings from database: {error_msg}. "
                "Default values are being used. Please check your database configuration and run migrations if needed.",
                extra_tags="alert-warning",
            )
            # Clear after adding message
            delattr(request, "system_settings_error")
    except Exception:
        # If we can't get settings, return empty dict (will cause errors elsewhere, but that's expected)
        return {}

    return {"system_settings": system_settings}


def bind_alert_count(request):
    if not settings.DISABLE_ALERT_COUNTER:

        if hasattr(request, "user") and request.user.is_authenticated:
            return {"alert_count": Alerts.objects.filter(user_id=request.user).count()}
    return {}


def bind_announcement(request):
    with contextlib.suppress(Exception):  # TODO: this should be replaced with more meaningful exception
        if request.user.is_authenticated:
            user_announcement = UserAnnouncement.objects.select_related(
                "announcement",
            ).get(user=request.user)
            return {"announcement": user_announcement.announcement}
    return {}


def session_expiry_notification(request):
    try:
        if request.user.is_authenticated:
            last_activity = request.session.get("_last_activity", time.time())
            expiry_time = last_activity + settings.SESSION_COOKIE_AGE  # When the session will expire
            warning_time = settings.SESSION_EXPIRE_WARNING  # Show warning X seconds before expiry
            notify_time = expiry_time - warning_time
        else:
            notify_time = None
    except Exception:
        return {}
    else:
        return {
            "session_notify_time": notify_time,
        }


def labels(request):
    return {
        "labels": get_labels(),
    }
