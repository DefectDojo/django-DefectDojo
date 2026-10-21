import datetime

from django.conf import settings
from django.utils import timezone

GITHUB_REPO_URL = "https://github.com/DefectDojo/django-DefectDojo"

# Key under UserContactInfo.user_state_details holding the GitHub star prompt state:
# {"starred": True} once the user clicked "Star on GitHub" (never shown again), or
# {"snoozed_until": "<ISO date>"} after "Later" / close.
GITHUB_STAR_PROMPT_KEY = "github_star_prompt"

# Don't ask brand-new users; let them use the product for a while first.
MIN_ACCOUNT_AGE = datetime.timedelta(days=7)
SNOOZE_DURATION = datetime.timedelta(days=30)


def should_show_github_star_prompt(user, now=None):
    if not settings.GITHUB_STAR_PROMPT_ENABLED:
        return False
    if not getattr(user, "is_authenticated", False):
        return False
    now = now or timezone.now()
    date_joined = getattr(user, "date_joined", None)
    if date_joined is None or now - date_joined < MIN_ACCOUNT_AGE:
        return False
    contact = getattr(user, "usercontactinfo", None)
    state = ((contact.user_state_details or {}) if contact is not None else {}).get(GITHUB_STAR_PROMPT_KEY) or {}
    if state.get("starred"):
        return False
    snoozed_until = state.get("snoozed_until")
    if snoozed_until:
        try:
            if now < datetime.datetime.fromisoformat(snoozed_until):
                return False
        except (TypeError, ValueError):
            pass  # corrupt value: treat as not snoozed
    return True


def github_star_prompt_state(choice, now=None):
    """Return the state to store for a "star" or "later" response, or None for an unknown choice."""
    if choice == "star":
        return {"starred": True}
    if choice == "later":
        now = now or timezone.now()
        return {"snoozed_until": (now + SNOOZE_DURATION).isoformat()}
    return None
