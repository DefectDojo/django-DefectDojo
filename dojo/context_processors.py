import contextlib

# import the settings file
from django.conf import settings
from django.contrib import messages

from dojo.announcement.os_message import get_os_banner
from dojo.labels import get_labels
from dojo.models import System_Settings, UserAnnouncement


def globalize_vars(request):
    # return the value you want as a dictionnary. you may add multiple values in there.
    context = {
        "SHOW_LOGIN_FORM": settings.SHOW_LOGIN_FORM,
        "FORGOT_PASSWORD": settings.FORGOT_PASSWORD,
        "FORGOT_USERNAME": settings.FORGOT_USERNAME,
        "CLASSIC_AUTH_ENABLED": settings.CLASSIC_AUTH_ENABLED,
        "DOCUMENTATION_URL": settings.DOCUMENTATION_URL,
        "API_TOKENS_ENABLED": settings.API_TOKENS_ENABLED,
        "API_TOKEN_AUTH_ENDPOINT_ENABLED": settings.API_TOKEN_AUTH_ENDPOINT_ENABLED,
        "SHOW_PLG_LINK": True,
        # V3 Feature Flags
        "V3_FEATURE_LOCATIONS": settings.V3_FEATURE_LOCATIONS,
    }

    additional_banners = []

    if (os_banner := get_os_banner()) is not None:
        additional_banners.append({
            "source": "os",
            "message": os_banner["message"],
            "style": "info",
            "url": "",
            "link_text": "",
            "expanded_html": os_banner["expanded_html"],
        })

    if hasattr(request, "session"):
        for banner in request.session.pop("_product_banners", []):
            additional_banners.append(banner)

    if additional_banners:
        context["additional_banners"] = additional_banners

    return context


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


def bind_announcement(request):
    with contextlib.suppress(Exception):  # TODO: this should be replaced with more meaningful exception
        if request.user.is_authenticated:
            user_announcement = UserAnnouncement.objects.select_related(
                "announcement",
            ).get(user=request.user)
            return {"announcement": user_announcement.announcement}
    return {}


from dojo.notifications.context_processors import (  # noqa: E402, F401  -- backward compat
    bind_alert_count,
    session_expiry_notification,
)


def labels(request):
    return {
        "labels": get_labels(),
    }
