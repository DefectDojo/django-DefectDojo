---
title: "Re-enabling login for SSO users (Open Source)"
description: "Give SSO-provisioned users a local password after moving to Open Source, where SSO is a Pro-only feature"
audience: opensource
weight: 2
---

## When this applies

SSO (SAML, OIDC, OAuth) is a [DefectDojo Pro](https://defectdojo.com) feature. If you upgrade to open-source DefectDojo 3.x (or otherwise move off Pro), the SSO login options are removed, and users who were provisioned through SSO can no longer log in. Their accounts were never given a local password, and the UI and API will not let you set one for them: DefectDojo detects them as SSO accounts and blocks the change.

You do **not** need to delete and recreate these users (which would lose their history, permissions, and object ownership). Instead, give each account a local password on the backend and force a password reset on next login.

See the [SSO section](/admin/sso/) and the [3.0 upgrade notes](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only) for background on SSO being Pro-only.

## Why it happens

Open-source DefectDojo authenticates against Django's local user database only. It decides whether an account is an "SSO user" purely by whether the account has a usable password. SSO-provisioned accounts were created with an *unusable* password, so:

* local login fails (there is no password to check), and
* the **Force password reset** control in the UI and API is blocked, with a message that the user is authorized through SSO.

Setting a real password clears both conditions at once: the account can log in locally, and the forced-reset flag becomes settable.

## The workaround

Run these steps from the Django shell inside the `uwsgi` container:

```bash
docker compose exec -it uwsgi ./manage.py shell
```

### A single user

```python
from dojo.user.models import Dojo_User, UserContactInfo

u = Dojo_User.objects.get(username="alice@example.com")
u.set_password("<temporary-strong-password>")   # makes the account a local login account
u.save()

uci, _ = UserContactInfo.objects.get_or_create(user=u)
uci.force_password_reset = True                  # force a change on next login
uci.save()
```

### All users without a usable password (bulk)

```python
from dojo.user.models import Dojo_User, UserContactInfo

for u in Dojo_User.objects.all():
    if not u.has_usable_password():
        u.set_password("<temporary-strong-password>")
        u.save()
        uci, _ = UserContactInfo.objects.get_or_create(user=u)
        uci.force_password_reset = True
        uci.save()
        print("reset:", u.username)
```

## What the user does next

Deliver the temporary password to each user out-of-band (email, your team chat, however you normally share secrets). On their next login, DefectDojo redirects them to the **Change Password** page and will not let them go anywhere else until they set their own password. The forced-reset flag clears automatically once they do.

If your instance has the "I forgot my password" flow enabled (`DD_FORGOT_PASSWORD`, on by default) and email configured, users can instead use the **I forgot my password** link on the login page after their account has a usable password, and set a password without needing the temporary one.

## Notes

* **Kubernetes:** run the shell in the Django pod instead, e.g. `kubectl exec -it deploy/defectdojo-django -c uwsgi -- ./manage.py shell` (adjust the deployment and container names to your release).
* Choose a strong throwaway password. With `force_password_reset = True` the user cannot keep it, so it only needs to survive one login.
* Keep at least one working local admin account so you are never locked out.
