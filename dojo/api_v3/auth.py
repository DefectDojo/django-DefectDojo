"""
Authentication for API v3 (D8 / §4.2).

Two modes, both active on every endpoint (registered as an ordered list ``[TokenAuth(),
django_auth]`` on the NinjaAPI instance):

- **Token** -- reuses the existing v2 DRF token store (``rest_framework.authtoken.models.Token``).
  A key that works on ``/api/v2/`` works on ``/api/v3/`` unchanged. No new model, no migration.
- **Session** -- Django session cookie + CSRF on unsafe methods, provided by ``ninja.security
  .django_auth`` (registered in ``dojo/api_v3/__init__.py``).

Each auth class returns ``None`` on no-match so the next one gets a chance; all failing yields a
401 problem+json. The token scheme is intentionally replaceable (I7): routes only ever see the
pluggable auth list, so the token backend can later be swapped with no route changes.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ninja.security import APIKeyHeader
from rest_framework.authtoken.models import Token

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractBaseUser
    from django.http import HttpRequest

# Header the token is read from; the ``Token `` prefix is parsed off in authenticate().
_TOKEN_PREFIX = "token"  # noqa: S105 -- scheme keyword, not a credential


class TokenAuth(APIKeyHeader):

    """Parse ``Authorization: Token <key>`` and resolve the request user from the v2 token store."""

    param_name = "Authorization"

    def authenticate(self, request: HttpRequest, key: str | None) -> AbstractBaseUser | None:
        if not key:
            return None
        parts = key.split()
        # Only handle the `Token <key>` scheme; anything else is left for session auth to try.
        if len(parts) != 2 or parts[0].lower() != _TOKEN_PREFIX:
            return None
        try:
            token = Token.objects.select_related("user").get(key=parts[1])
        except Token.DoesNotExist:
            return None
        user = token.user
        if not user.is_active:
            return None
        # Set request.user so downstream authorized-queryset helpers (I8) resolve the right user
        # exactly as they do for session auth.
        request.user = user
        return user
