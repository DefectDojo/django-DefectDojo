"""
Scalar API reference page for API v3 (§12: supersedes the OS6 Scalar deferral).

Serves a minimal HTML shell that loads the Scalar reference UI **from the jsDelivr CDN with a
pinned version and a Subresource Integrity (SRI) hash** — the architect-approved middle path
between "vendor an unreviewed 3.7 MB JS bundle into a security product's repo" (the OS6 concern)
and "trust a mutable CDN URL":

- The version is pinned (never ``@latest``), and jsDelivr caches versioned artifacts permanently.
- The SRI hash makes the browser REFUSE to execute the bundle if the CDN ever serves different
  bytes — supply-chain integrity is enforced client-side, with only a hash committed to the repo.
- The page is progressive enhancement: ninja's built-in Swagger at ``/docs`` ships its assets
  locally and remains the always-works default (air-gapped deployments cannot reach the CDN, so
  this page intentionally degrades there while ``/docs`` keeps working).

To upgrade Scalar: fetch the new pinned bundle, recompute ``openssl dgst -sha384 -binary | base64``,
and update the two constants below together.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from django.http import HttpResponse
from django.urls import reverse

if TYPE_CHECKING:
    from django.http import HttpRequest

# Pin + hash MUST change together (see module docstring).
SCALAR_CDN_URL = "https://cdn.jsdelivr.net/npm/@scalar/api-reference@1.63.0/dist/browser/standalone.min.js"
SCALAR_SRI_HASH = "sha384-bnRzGcRYqM9jbXxeIbNDWWD8mNMY0p8qvmfAyfcT5S7/I6E7bsyLprA0uIP2gUu7"

_PAGE = """<!doctype html>
<html>
<head>
  <title>DefectDojo API v3 Reference</title>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
</head>
<body>
  <noscript>The interactive API reference requires JavaScript.
    The OpenAPI schema is at <a href="{openapi_url}">{openapi_url}</a>;
    Swagger UI (works offline) is at <a href="{docs_url}">{docs_url}</a>.</noscript>
  <script id="api-reference" data-url="{openapi_url}"></script>
  <script src="{cdn_url}" integrity="{sri_hash}" crossorigin="anonymous"></script>
</body>
</html>"""


def scalar_reference(request: HttpRequest) -> HttpResponse:
    """Render the Scalar reference shell (no data of its own — the schema URL does the work)."""
    return HttpResponse(_PAGE.format(
        openapi_url=reverse("api_v3:openapi-json"),
        docs_url=reverse("api_v3:openapi-view"),
        cdn_url=SCALAR_CDN_URL,
        sri_hash=SCALAR_SRI_HASH,
    ))
