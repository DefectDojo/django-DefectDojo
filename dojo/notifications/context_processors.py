import time

from django.conf import settings

from dojo.notifications.models import Alerts


def bind_alert_count(request):
    if not settings.DISABLE_ALERT_COUNTER:

        if hasattr(request, "user") and request.user.is_authenticated:
            return {"alert_count": Alerts.objects.filter(user_id=request.user).count()}
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
