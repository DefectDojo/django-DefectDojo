"""
Who may set which email on an account, and the link that proves a person owns a new address.

The email is what a password reset is sent to, and what single sign-on can match an account by, so an
address on an account is an identity claim. Three rules follow:

* A new email is unique: no other account holds it, compared ignoring case. Only a new value is checked,
  so accounts that already share an address keep working and can still edit everything else.
* A user changing their own email proves they own the new address first: with
  ``EMAIL_CHANGE_CONFIRMATION_ENABLED`` on, the change waits for a link sent to that address; with it off
  (the default, since no mail server is set up out of the box) they cannot change it, and an
  administrator does it for them.
* A user who signs in through single sign-on never changes their own email: the identity provider owns it.
"""

import logging

from django.conf import settings
from django.core import signing
from django.core.mail import send_mail
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.models import Dojo_User
from dojo.utils import get_system_setting

logger = logging.getLogger(__name__)

#: Separates these signed links from every other use of the secret key.
TOKEN_SALT = "dojo.user.email_ownership.change"  # noqa: S105 (a signing namespace, not a secret)
#: The rate limiter's name for confirmation emails (``account_email_allowed``).
MAIL_KIND = "email-change"


def _normalized(email):
    return (email or "").strip().lower()


def email_taken(email, *, exclude_pk=None):
    """Whether an account other than ``exclude_pk`` holds ``email``, ignoring case."""
    if not _normalized(email):
        return False
    holders = Dojo_User.objects.filter(email__iexact=email.strip())
    if exclude_pk is not None:
        holders = holders.exclude(pk=exclude_pk)
    return holders.exists()


def is_new_email(user, email):
    """Whether ``email`` differs from the address ``user`` holds now (always, for an account not yet saved)."""
    if user is None or user.pk is None:
        return True
    return _normalized(email) != _normalized(user.email)


def taken_email_error(user, email):
    """The error for setting ``email`` on ``user``, or ``None``. An unchanged address is never refused."""
    if is_new_email(user, email) and email_taken(email, exclude_pk=getattr(user, "pk", None)):
        return _("This email address is already used by another account.")
    return None


def confirmation_enabled():
    """Whether a self-service email change is confirmed by a link (``DD_EMAIL_CHANGE_CONFIRMATION_ENABLED``)."""
    return bool(getattr(settings, "EMAIL_CHANGE_CONFIRMATION_ENABLED", False))


def signs_in_with_sso(user):
    """Whether ``user`` signs in through an identity provider: open source knows it as an account with no password."""
    return not user.has_usable_password()


def self_service_refusal(user, *, sso_user=None):
    """
    Why ``user`` may not change their own email, or ``None`` when they may (through a confirmation link).

    A superuser is an administrator and changes any email directly, so this is never asked for one.
    ``sso_user`` lets an edition that knows more about sign-in than open source answer that part.
    """
    if signs_in_with_sso(user) if sso_user is None else sso_user:
        return _("Your email address comes from your identity provider. Change it there.")
    if not confirmation_enabled():
        return _("Ask an administrator to change your email address.")
    return None


def api_self_change_refusal(acting_user, user, email):
    """
    Why ``acting_user`` may not set ``email`` on ``user`` through a user API, or ``None``.

    The user APIs save at once and send no confirmation link, so a non-superuser editing their own record
    there (they hold the user-management permissions) changes their email from the profile instead, where the
    rules above apply. A superuser, another account (gated by the identity-field rule) and an unchanged address
    are not this rule's business.
    """
    if user is None or acting_user.is_superuser or user.pk != acting_user.pk or not is_new_email(user, email):
        return None
    return self_service_refusal(user) or _(
        "Change your own email address from your profile, which sends a confirmation link to the new address.",
    )


def make_token(user, new_email):
    """A signed, expiring link token that moves ``user`` from their current email to ``new_email``."""
    return signing.dumps({"user": user.pk, "from": user.email or "", "to": new_email}, salt=TOKEN_SALT, compress=True)


def send_confirmation(request, user, new_email):
    """
    Email ``new_email`` the link that confirms it for ``user``. Returns whether a message was sent.

    The address never receives more than the account-recovery limit of these an hour.
    """
    from dojo.user.ui.views import account_email_allowed  # noqa: PLC0415 (the views import this module)

    if not account_email_allowed(MAIL_KIND, new_email):
        return False
    link = request.build_absolute_uri(reverse("confirm_email_change", args=(make_token(user, new_email),)))
    subject = _("Confirm your new DefectDojo email address")
    body = _(
        "Someone asked to use this address for the DefectDojo account %(username)s.\n\n"
        "To confirm it, open this link while signed in as %(username)s:\n\n%(link)s\n\n"
        "The link works once and expires. If you did not ask for this, ignore this email: nothing changes.",
    ) % {"username": user.username, "link": link}
    try:
        send_mail(subject, body, get_system_setting("email_from") or None, [new_email])
    except Exception:
        logger.exception("Could not send the email change confirmation for user %s", user.pk)
        return False
    logger.info("Sent an email change confirmation for user %s", user.pk)
    return True


def confirm(user, token):
    """
    Apply the change ``token`` asks for to ``user``. Returns ``None`` on success, else the reason it was refused.

    A link is refused once it expires, when it was made for another account, once the account's email is no
    longer the one it was made from (so a used or superseded link never applies again), and when the new
    address has meanwhile been taken by another account.
    """
    try:
        claim = signing.loads(token, salt=TOKEN_SALT, max_age=settings.PASSWORD_RESET_TIMEOUT)
    except signing.SignatureExpired:
        return _("This confirmation link has expired. Change your email again to get a new one.")
    except signing.BadSignature:
        return _("This confirmation link is not valid.")
    if claim.get("user") != user.pk or (user.email or "") != claim.get("from"):
        return _("This confirmation link is not valid.")
    if refusal := taken_email_error(user, claim.get("to")):
        return refusal
    user.email = claim["to"]
    user.save(update_fields=["email"])
    logger.info("User %s confirmed a new email address", user.pk)
    return None
