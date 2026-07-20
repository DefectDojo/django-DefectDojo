"""
Deny-by-default authorization sweep for API v3 (§5 I8, §10).

Enforces the RBAC invariant (I8) *structurally* across the **whole mounted surface**: every
operation in ``api_v3.get_openapi_schema()`` -- all methods, all paths -- is probed twice, and a
completeness gate (identical in spirit to ``test_apiv3_query_report.py``) fails the moment an
operation exists in the schema without a registered probe, so the sweep can never silently fall
behind a new endpoint.

Two probes per operation:

1. **Anonymous** -> must be **401**. Ninja runs authentication in ``Operation._run_checks`` *before*
   it parses path/query/body (``_get_values``), so an anonymous request never reaches request
   validation and needs no payload (confirmed by ``test_apiv3_auth``: anonymous GET -> 401 problem+
   json, v3 is in ``LOGIN_EXEMPT_URLS`` so there is no login redirect).

2. **Zero-permission user** -- a freshly created, authenticated user with **no** memberships, roles
   or configuration permissions -- must **NEVER receive data**:

   * ``GET`` list          -> 200 with ``count == 0`` / ``results == []`` (RBAC-scoped empty);
     ``/findings`` additionally checked with ``?include=counts`` (all totals must be 0);
     ``/locations`` is the superuser-gated exception -> **403**;
     ``/users`` is the documented self-visibility exception -> 200 with **exactly the caller's own
     record** (§12 OS3a: a user always sees themselves and nobody else -- not a leak).
   * ``GET`` detail / sub-resource ``GET`` -> **404** (unknown-or-unauthorized, never leak
     existence, §4.10); ``/locations/{id}`` -> **403** (superuser gate).
   * writes (POST/PATCH/PUT/DELETE) -> **403 or 404**. Each write probe carries a *minimal valid
     payload* referencing fixture ids that exist but are NOT authorized for the zero-perm user, so
     it gets past ninja request-validation and genuinely reaches the authorization gate. **A
     400/422 on a write probe is a sweep FAILURE** -- it means validation, not authz, produced the
     denial (the gate was never exercised). The registry below reaches the gate for every write, so
     there are zero validation-blocked probes.

Because the whole thing is registry-driven and gated for completeness, any future endpoint fails
``test_sweep_covers_every_operation`` until a probe (request + expected outcome) is added for it.
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from typing import TYPE_CHECKING

from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile

from dojo.api_v3.api import api_v3
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)

from .base import ApiV3TestCase

if TYPE_CHECKING:
    from rest_framework.test import APIClient

_HTTP_METHODS = {"get", "post", "put", "patch", "delete"}


@dataclass
class Probe:

    """One operation's representative request + its expected deny outcomes."""

    method: str          # HTTP verb, upper-case
    path: str            # OpenAPI mount-relative template, e.g. "/findings/{finding_id}"
    url: str             # concrete request URL (fixture ids substituted)
    zero_status: int     # expected status for the zero-permission user
    payload: object = None       # request body for the zero-perm write probe (dict) or None
    fmt: str = "json"            # "json" | "multipart"
    list_kind: str | None = None  # "empty" | "findings" | "users_self" -> zero-perm list assertion
    note: str = ""               # documentation / justification for the chosen outcome

    @property
    def key(self) -> tuple[str, str]:
        return (self.method, self.path)


class TestApiV3AuthzSweep(ApiV3TestCase):

    """Whole-surface deny-by-default sweep: anonymous -> 401, zero-perm -> never any data."""

    def setUp(self):
        super().setUp()
        # A brand-new authenticated user with zero authorization: no product/type membership, no
        # role, no configuration permission. Mirrors the "limited"/"member-before-grant" users the
        # other v3 RBAC tests rely on (test_apiv3_finding_writes / test_apiv3_expand_rbac), which
        # confirm a freshly created user sees nothing.
        self.zero = Dojo_User.objects.create_user(username="v3_authz_zero", password="x")  # noqa: S106
        self.zero_client: APIClient = self.token_client(user=self.zero)

        # Fixture objects the zero-perm user is NOT authorized for. They exist (so the write probes
        # reach the authorization gate rather than 404-ing on a non-existent id where the outcome
        # would be ambiguous) but are invisible to the zero-perm user's authorized querysets.
        self.finding = Finding.objects.first()
        self.test = Test.objects.first()
        self.engagement = Engagement.objects.first()
        self.asset = Product.objects.first()
        self.organization = Product_Type.objects.first()
        self.test_type = Test_Type.objects.first()

    # --- schema introspection -----------------------------------------------------------------
    def _schema_operations(self) -> set[tuple[str, str]]:
        """Every (METHOD, mount-relative path) in the live OpenAPI schema (the completeness set)."""
        schema = api_v3.get_openapi_schema()
        ops: set[tuple[str, str]] = set()
        for path, item in schema["paths"].items():
            # Schema paths carry the mount prefix (/api/v3-alpha/...); compare mount-relative,
            # exactly as test_apiv3_query_report does.
            rel = "/" + path.split(settings.API_V3_URL_PREFIX, 1)[-1].lstrip("/")
            for method in item:
                if method.lower() in _HTTP_METHODS:
                    ops.add((method.upper(), rel))
        return ops

    # --- probe registry -----------------------------------------------------------------------
    def _file_payload(self) -> dict:
        """Fresh multipart body for a file/import write probe (a tiny scan file)."""
        return {
            "title": "authz-sweep-file",
            "file": SimpleUploadedFile("authz-sweep.txt", b"authz sweep body", content_type="text/plain"),
        }

    def _sub_probes(self, resource: str, parent_id: int, *, notes: bool, files: bool, tags: bool) -> list[Probe]:
        """
        Sub-resource probes (§4.12). Every one is parent-inherited: the zero-perm user cannot see
        the parent, so the parent resolves to None through its authorized-view queryset -> 404,
        before any note/file/tag is touched (never leak existence, never mutate).
        """
        base = f"/{resource}/{{parent_id}}"
        probes: list[Probe] = []
        if notes:
            probes += [
                Probe("GET", f"{base}/notes", self.v3_url(f"{resource}/{parent_id}/notes"), 404),
                Probe("POST", f"{base}/notes", self.v3_url(f"{resource}/{parent_id}/notes"), 404,
                      payload={"entry": "authz sweep"}),
            ]
        if files:
            probes += [
                Probe("GET", f"{base}/files", self.v3_url(f"{resource}/{parent_id}/files"), 404),
                Probe("POST", f"{base}/files", self.v3_url(f"{resource}/{parent_id}/files"), 404,
                      payload=self._file_payload(), fmt="multipart"),
                # file_id is irrelevant: parent-view 404 fires before the file lookup.
                Probe("GET", f"{base}/files/{{file_id}}/download",
                      self.v3_url(f"{resource}/{parent_id}/files/1/download"), 404),
            ]
        if tags:
            probes += [
                Probe("GET", f"{base}/tags", self.v3_url(f"{resource}/{parent_id}/tags"), 404),
                Probe("PUT", f"{base}/tags", self.v3_url(f"{resource}/{parent_id}/tags"), 404,
                      payload={"tags": ["authz"]}),
                Probe("POST", f"{base}/tags", self.v3_url(f"{resource}/{parent_id}/tags"), 404,
                      payload={"tags": ["authz"]}),
                Probe("DELETE", f"{base}/tags/{{tag}}",
                      self.v3_url(f"{resource}/{parent_id}/tags/authz"), 404),
            ]
        return probes

    def _probes(self) -> list[Probe]:
        f, e, t = self.finding.id, self.engagement.id, self.test.id
        a, o, tt = self.asset.id, self.organization.id, self.test_type.id
        admin_id = self.admin.id
        p: list[Probe] = []

        # ---- findings (list supports include=counts) -----------------------------------------
        p += [
            Probe("GET", "/findings", self.v3_url("findings"), 200, list_kind="findings"),
            Probe("GET", "/findings/{finding_id}", self.v3_url(f"findings/{f}"), 404),
            Probe("POST", "/findings", self.v3_url("findings"), 403,
                  payload={"test": t, "title": "authz sweep", "severity": "High",
                           "description": "x", "active": True, "verified": False},
                  note="existing but unauthorized test -> Finding_Add gate -> 403"),
            Probe("PATCH", "/findings/{finding_id}", self.v3_url(f"findings/{f}"), 404,
                  payload={"severity": "Low"}, note="finding invisible to zero-perm queryset -> 404"),
            Probe("PUT", "/findings/{finding_id}", self.v3_url(f"findings/{f}"), 404,
                  payload={"title": "authz sweep", "severity": "High", "description": "x",
                           "active": True, "verified": False},
                  note="full replace: finding invisible to zero-perm queryset -> 404 before edit gate"),
            Probe("DELETE", "/findings/{finding_id}", self.v3_url(f"findings/{f}"), 404),
            Probe("GET", "/findings/{finding_id}/locations", self.v3_url(f"findings/{f}/locations"), 404),
            Probe("GET", "/findings/export.csv", self.v3_url("findings/export.csv"), 200, list_kind="csv_empty",
                  note="CSV export: zero-perm -> header-only CSV over the RBAC-scoped empty queryset"),
        ]
        p += self._sub_probes("findings", f, notes=True, files=True, tags=True)

        # ---- organizations (product_type) ----------------------------------------------------
        p += [
            Probe("GET", "/organizations", self.v3_url("organizations"), 200, list_kind="empty"),
            Probe("GET", "/organizations/{organization_id}", self.v3_url(f"organizations/{o}"), 404),
            Probe("POST", "/organizations", self.v3_url("organizations"), 403,
                  payload={"name": "authz sweep org"},
                  note="no global add permission -> 403"),
            Probe("PATCH", "/organizations/{organization_id}", self.v3_url(f"organizations/{o}"), 404,
                  payload={"name": "x"}),
            Probe("PUT", "/organizations/{organization_id}", self.v3_url(f"organizations/{o}"), 404,
                  payload={"name": "x"}, note="full replace: organization invisible -> 404"),
            Probe("DELETE", "/organizations/{organization_id}", self.v3_url(f"organizations/{o}"), 404),
            Probe("GET", "/organizations/export.csv", self.v3_url("organizations/export.csv"), 200,
                  list_kind="csv_empty", note="CSV export: zero-perm -> header-only CSV (RBAC-scoped empty)"),
        ]

        # ---- assets (product) ----------------------------------------------------------------
        p += [
            Probe("GET", "/assets", self.v3_url("assets"), 200, list_kind="empty"),
            Probe("GET", "/assets/{asset_id}", self.v3_url(f"assets/{a}"), 404),
            Probe("POST", "/assets", self.v3_url("assets"), 403,
                  payload={"name": "authz sweep asset", "description": "x", "organization": o},
                  note="existing but unauthorized organization -> Product_Type_Add_Product gate -> 403"),
            Probe("PATCH", "/assets/{asset_id}", self.v3_url(f"assets/{a}"), 404, payload={"name": "x"}),
            Probe("PUT", "/assets/{asset_id}", self.v3_url(f"assets/{a}"), 404,
                  payload={"name": "x", "description": "y", "organization": o},
                  note="full replace: asset invisible -> 404 before edit gate"),
            Probe("DELETE", "/assets/{asset_id}", self.v3_url(f"assets/{a}"), 404),
            Probe("GET", "/assets/{asset_id}/locations", self.v3_url(f"assets/{a}/locations"), 404),
            Probe("GET", "/assets/export.csv", self.v3_url("assets/export.csv"), 200, list_kind="csv_empty",
                  note="CSV export: zero-perm -> header-only CSV (RBAC-scoped empty)"),
        ]
        p += self._sub_probes("assets", a, notes=False, files=False, tags=True)

        # ---- engagements ---------------------------------------------------------------------
        p += [
            Probe("GET", "/engagements", self.v3_url("engagements"), 200, list_kind="empty"),
            Probe("GET", "/engagements/{engagement_id}", self.v3_url(f"engagements/{e}"), 404),
            Probe("POST", "/engagements", self.v3_url("engagements"), 403,
                  payload={"asset": a, "target_start": "2026-01-01", "target_end": "2026-01-02"},
                  note="existing but unauthorized asset -> Engagement_Add gate -> 403"),
            Probe("PATCH", "/engagements/{engagement_id}", self.v3_url(f"engagements/{e}"), 404,
                  payload={"name": "x"}),
            Probe("PUT", "/engagements/{engagement_id}", self.v3_url(f"engagements/{e}"), 404,
                  payload={"asset": a, "target_start": "2026-01-01", "target_end": "2026-01-02"},
                  note="full replace: engagement invisible -> 404 before edit gate"),
            Probe("DELETE", "/engagements/{engagement_id}", self.v3_url(f"engagements/{e}"), 404),
            Probe("GET", "/engagements/export.csv", self.v3_url("engagements/export.csv"), 200,
                  list_kind="csv_empty", note="CSV export: zero-perm -> header-only CSV (RBAC-scoped empty)"),
        ]
        p += self._sub_probes("engagements", e, notes=True, files=True, tags=True)

        # ---- tests ---------------------------------------------------------------------------
        p += [
            Probe("GET", "/tests", self.v3_url("tests"), 200, list_kind="empty"),
            Probe("GET", "/tests/{test_id}", self.v3_url(f"tests/{t}"), 404),
            Probe("POST", "/tests", self.v3_url("tests"), 403,
                  payload={"engagement": e, "test_type": tt,
                           "target_start": "2026-01-01T00:00:00Z", "target_end": "2026-01-02T00:00:00Z"},
                  note="existing but unauthorized engagement -> Test_Add gate -> 403"),
            Probe("PATCH", "/tests/{test_id}", self.v3_url(f"tests/{t}"), 404, payload={"title": "x"}),
            Probe("PUT", "/tests/{test_id}", self.v3_url(f"tests/{t}"), 404,
                  payload={"test_type": tt, "target_start": "2026-01-01T00:00:00Z",
                           "target_end": "2026-01-02T00:00:00Z"},
                  note="full replace: test invisible -> 404 before edit gate"),
            Probe("DELETE", "/tests/{test_id}", self.v3_url(f"tests/{t}"), 404),
            Probe("GET", "/tests/export.csv", self.v3_url("tests/export.csv"), 200, list_kind="csv_empty",
                  note="CSV export: zero-perm -> header-only CSV (RBAC-scoped empty)"),
        ]
        p += self._sub_probes("tests", t, notes=True, files=True, tags=True)

        # ---- users (self-visibility exception on list/detail; writes admin-only) -------------
        p += [
            Probe("GET", "/users", self.v3_url("users"), 200, list_kind="users_self",
                  note="a user always sees exactly their own record and no other (§12 OS3a) -- not a leak"),
            # Target the admin's id: invisible to the zero-perm user's self-only queryset -> 404.
            Probe("GET", "/users/{user_id}", self.v3_url(f"users/{admin_id}"), 404),
            Probe("POST", "/users", self.v3_url("users"), 403,
                  payload={"username": "authz_sweep_new", "email": "authz@example.com"},
                  note="no auth.add_user configuration permission -> 403"),
            Probe("PATCH", "/users/{user_id}", self.v3_url(f"users/{admin_id}"), 404,
                  payload={"first_name": "x"}, note="admin invisible to zero-perm self-scope -> 404"),
            Probe("PUT", "/users/{user_id}", self.v3_url(f"users/{admin_id}"), 404,
                  payload={"username": "authz_sweep_put", "email": "authzput@example.com"},
                  note="full replace: admin invisible to zero-perm self-scope -> 404"),
            Probe("DELETE", "/users/{user_id}", self.v3_url(f"users/{admin_id}"), 404),
            Probe("GET", "/users/export.csv", self.v3_url("users/export.csv"), 200, list_kind="csv_users_self",
                  note="CSV export: self-visibility scope -> exactly the caller's own record, no other (§12 OS3a)"),
        ]

        # ---- locations (superuser-gated: 403 before any object lookup) -----------------------
        p += [
            Probe("GET", "/locations", self.v3_url("locations"), 403,
                  note="v2 LocationViewSet is IsSuperUser -> mirrored 403 for non-superusers (§12 OS4)"),
            Probe("GET", "/locations/{location_id}", self.v3_url("locations/1"), 403,
                  note="superuser gate fires before the id lookup"),
            Probe("GET", "/locations/export.csv", self.v3_url("locations/export.csv"), 403,
                  note="CSV export inherits the /locations superuser gate -> 403 before streaming (§12 OS4)"),
        ]

        # ---- consolidated import -------------------------------------------------------------
        import_payload = self._file_payload()
        import_payload.update({"scan_type": "ZAP Scan", "mode": "import", "engagement": e})
        p += [
            Probe("POST", "/import", self.v3_url("import"), 403,
                  payload=import_payload, fmt="multipart",
                  note="mode=import + existing but unauthorized engagement -> UserHasImportPermission -> 403"),
        ]
        return p

    # --- dispatch -----------------------------------------------------------------------------
    def _dispatch(self, client: APIClient, probe: Probe, *, with_payload: bool):
        fn = getattr(client, probe.method.lower())
        if with_payload and probe.payload is not None:
            return fn(probe.url, probe.payload, format=probe.fmt)
        return fn(probe.url)

    @staticmethod
    def _read_csv(response) -> list[list[str]]:
        """Consume a streaming CSV export response into a list of rows (header first)."""
        content = b"".join(response.streaming_content).decode("utf-8")
        return list(csv.reader(io.StringIO(content)))

    def _assert_zero_list(self, probe: Probe, response) -> None:
        label = f"{probe.method} {probe.path}"
        if probe.list_kind in {"csv_empty", "csv_users_self"}:
            # CSV export projection of the deny-by-default invariant: a zero-perm user gets a valid
            # CSV whose data body is empty (header only) -- except /users, the documented
            # self-visibility scope, where the export contains exactly the caller's own record and no
            # other (identical filter contract + RBAC queryset as the /users list, §12 OS3a).
            rows = self._read_csv(response)
            self.assertGreaterEqual(len(rows), 1, f"{label}: a CSV export must always emit a header row")
            header, data_rows = rows[0], rows[1:]
            self.assertIn("id", header, f"{label}: CSV header must include the id column")
            if probe.list_kind == "csv_empty":
                self.assertEqual([], data_rows, f"{label}: zero-perm CSV export must be header-only (no data rows)")
                return
            self.assertEqual(
                1, len(data_rows), f"{label}: users CSV export must return exactly the caller's own record",
            )
            self.assertEqual(
                str(self.zero.id), data_rows[0][header.index("id")],
                f"{label}: users CSV export leaked a record other than the caller's own",
            )
            return
        body = response.json()
        if probe.list_kind == "users_self":
            # The one documented deviation: a zero-perm user sees exactly their own record and no
            # other user's data. Anything else (count 0, or a foreign row) would be a regression.
            self.assertEqual(1, body["count"], f"{label}: users list must return exactly the caller's own record")
            self.assertEqual(
                [self.zero.id], [row["id"] for row in body["results"]],
                f"{label}: users list leaked a record other than the caller's own",
            )
            return
        # Every other list must be RBAC-scoped empty for a zero-permission user.
        self.assertEqual(0, body["count"], f"{label}: expected an empty (RBAC-scoped) list, got count={body['count']}")
        self.assertEqual([], body["results"], f"{label}: expected results == [] for a zero-permission user")
        if probe.list_kind == "findings":
            # include=counts must aggregate over the (empty) authorized queryset -> all zero.
            counts = self.get_json(
                "findings", client=self.zero_client, data={"include": "counts"},
            )["meta"]["counts"]
            self.assertEqual(0, counts["total"], f"{label}: include=counts total must be 0 for a zero-perm user")
            for sev, n in counts["severity"].items():
                self.assertEqual(0, n, f"{label}: include=counts severity[{sev}] must be 0, got {n}")

    # --- tests --------------------------------------------------------------------------------
    def test_sweep_covers_every_operation(self):
        """Completeness gate: every schema operation must have exactly one registered probe."""
        registered = {probe.key for probe in self._probes()}
        schema_ops = self._schema_operations()

        missing = schema_ops - registered
        self.assertFalse(
            missing,
            f"operation(s) {sorted(missing)} have no entry in the authorization sweep -- add a "
            f"representative request + expected outcome to _probes() (deliberate: every new "
            f"endpoint must be authorization-probed before it can ship).",
        )
        extra = registered - schema_ops
        self.assertFalse(
            extra,
            f"authorization sweep probes {sorted(extra)} no longer match any schema operation -- "
            f"remove or fix the stale probe(s).",
        )
        # Guard against accidental duplicate probes silently masking a gap.
        keys = [probe.key for probe in self._probes()]
        self.assertEqual(len(keys), len(set(keys)), "duplicate probe keys in _probes()")

    def test_anonymous_is_401_on_every_operation(self):
        """Probe (a): an unauthenticated request is 401 on every operation (auth before body parse)."""
        failures = []
        for probe in self._probes():
            response = self._dispatch(self.anonymous_client(), probe, with_payload=False)
            if response.status_code != 401:
                failures.append(f"{probe.method} {probe.path} -> {response.status_code} (expected 401)")
        self.assertFalse(failures, "anonymous requests must be 401:\n" + "\n".join(failures))

    def test_zero_permission_user_never_receives_data(self):
        """Probe (b): a fully authenticated but zero-permission user never receives/mutates data."""
        failures = []
        for probe in self._probes():
            response = self._dispatch(self.zero_client, probe, with_payload=True)
            label = f"{probe.method} {probe.path}"
            # A write probe that 400/422s never reached the authz gate -- that is a sweep failure.
            if probe.method != "GET" and response.status_code in {400, 422}:
                failures.append(
                    f"{label} -> {response.status_code}: write probe blocked at request VALIDATION, "
                    f"not authorization -- fix the probe payload so it reaches the authz gate "
                    f"(body: {response.content[:200]!r})",
                )
                continue
            if response.status_code != probe.zero_status:
                failures.append(
                    f"{label} -> {response.status_code} (expected {probe.zero_status})"
                    f"{' [' + probe.note + ']' if probe.note else ''} "
                    f"body: {response.content[:200]!r}",
                )
                continue
            if response.status_code == 200 and probe.list_kind is not None:
                self._assert_zero_list(probe, response)
        self.assertFalse(
            failures,
            "zero-permission user received an unexpected outcome (potential authorization gap):\n"
            + "\n".join(failures),
        )

    def test_zero_perm_lists_empty_but_admin_sees_data(self):
        """
        Sanity contrast proving the zero-perm empties are *authorization*, not an empty DB: the
        admin (superuser) sees rows on the same lists where the zero-perm user sees none.
        """
        for resource in ("findings", "organizations", "assets", "engagements", "tests"):
            admin_body = self.get_json(resource)
            self.assertGreater(
                admin_body["count"], 0,
                f"fixture has no {resource} for the admin -- the empty-list contrast is meaningless",
            )
            zero_body = self.get_json(resource, client=self.zero_client)
            self.assertEqual(0, zero_body["count"], f"zero-perm user unexpectedly sees {resource}")
        # Locations: admin (superuser) 200, zero-perm 403 (superuser gate).
        self.get_json("locations")
        self.get_json("locations", client=self.zero_client, expected=403)
        # Users: admin sees many; zero-perm sees only itself.
        self.assertGreater(self.get_json("users")["count"], 1)
        self.assertEqual(1, self.get_json("users", client=self.zero_client)["count"])
