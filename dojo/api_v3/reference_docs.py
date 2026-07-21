"""
Scalar API reference page for API v3 (§12: supersedes the OS6 Scalar deferral and the interim
CDN+SRI approach).

Serves a minimal HTML shell that loads the Scalar reference UI **from our own static files** —
the bundle is installed at image-build time via the existing components yarn step
(``components/package.json`` pins ``@scalar/api-reference`` to an exact version;
``components/yarn.lock`` carries its integrity hashes) and is served through the standard
static pipeline, because ``STATICFILES_DIRS`` already includes ``components/node_modules``.

Why this shape (architect decision):

- **No CDN at runtime**: the asset ships inside the image like every other yarn-managed frontend
  dependency, so air-gapped deployments get a working reference page and no usage metadata leaks
  to a third party.
- **No vendored blob in git**: only the one-line pin lands in the repo; integrity is enforced by
  the yarn lockfile at image build instead of a browser SRI attribute at runtime.
- ninja's built-in Swagger at ``/docs`` remains available as a second, framework-bundled UI.

To upgrade Scalar: bump the exact pin in ``components/package.json`` (``yarn add
@scalar/api-reference@<ver> --exact``) — nothing in this module changes.

Dev note: without the yarn install (bare-metal dev before ``yarn`` has run in ``components/``),
the page shell renders but the script 404s — the same behaviour as every other yarn-built asset;
``/docs`` always works.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from django.http import HttpResponse
from django.templatetags.static import static
from django.urls import reverse

if TYPE_CHECKING:
    from django.http import HttpRequest

# Path inside components/node_modules (a STATICFILES_DIRS entry); version pinned in package.json.
SCALAR_STATIC_PATH = "@scalar/api-reference/dist/browser/standalone.js"

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
    Swagger UI is at <a href="{docs_url}">{docs_url}</a>.</noscript>
  <script id="api-reference" data-url="{openapi_url}"></script>
  <script src="{script_url}"></script>
</body>
</html>"""


def scalar_reference(request: HttpRequest) -> HttpResponse:
    """Render the Scalar reference shell (no data of its own — the schema URL does the work)."""
    return HttpResponse(_PAGE.format(
        openapi_url=reverse("api_v3:openapi-json"),
        docs_url=reverse("api_v3:openapi-view"),
        script_url=static(SCALAR_STATIC_PATH),
    ))
