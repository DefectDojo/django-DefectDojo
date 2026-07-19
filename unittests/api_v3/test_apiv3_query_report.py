"""
Whole-surface query sweep for API v3 (§7 / OS6 verification).

Two guarantees on every mounted v3 GET endpoint:

1. **No N+1 signature** — no normalized query shape repeats >= ``_THRESHOLD`` times within one
   request (the per-list ``assertNumQueries`` tests pin totals; this test identifies the shape
   when something regresses, across the whole surface at once).
2. **Completeness** — every GET path in the OpenAPI schema must have a representative request
   below. Adding a resource without extending the sweep fails the test, so OS4/OS5+ endpoints
   are covered by construction.

The full capture is always written to ``/tmp/apiv3_query_report.md`` for review.
"""
from __future__ import annotations

from pathlib import Path

from django.conf import settings

from dojo.api_v3.api import api_v3
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.models import Engagement, Finding, Product, Product_Type, Test

from .base import ApiV3TestCase
from .query_report import capture_request, format_report

_THRESHOLD = 4
_REPORT_PATH = Path("/tmp/apiv3_query_report.md")
# POST-only paths (no GET operation) are exempt from the completeness check.
_ROW_FANOUT = 15  # enough rows that any per-row query trips the threshold unmistakably


class TestApiV3QueryReport(ApiV3TestCase):

    """Sweep every mounted v3 GET route; flag N+1 shapes; enforce sweep completeness."""

    def setUp(self):
        super().setUp()  # base gives self.client = admin token client: RBAC never hides rows here
        self._fan_out_rows()

    def _fan_out_rows(self):
        """Clone fixture rows so per-row queries repeat >= threshold and cannot hide."""
        finding = Finding.objects.first()
        for i in range(_ROW_FANOUT):
            clone = Finding.objects.get(pk=finding.pk)
            clone.pk = None
            clone.title = f"query-report fanout {i}"
            clone.save()
        prod_type = Product_Type.objects.first()
        for i in range(_ROW_FANOUT):
            Product_Type.objects.create(name=f"query-report pt {i}")
        for i in range(_ROW_FANOUT):
            Product.objects.create(
                name=f"query-report product {i}",
                description="query report fanout",
                prod_type=prod_type,
            )
        for model in (Engagement, Test):
            template = model.objects.first()
            if template is None:
                continue
            for _ in range(_ROW_FANOUT):
                clone = model.objects.get(pk=template.pk)
                clone.pk = None
                clone.save()
        # Fan out location edges so the sub-resource per-row queries (if any) trip the threshold.
        self._loc_finding = Finding.objects.order_by("pk").first()
        self._loc_product = Product.objects.order_by("pk").first()
        for i in range(_ROW_FANOUT):
            loc = Location.objects.create(location_type="url", location_value=f"query-report loc {i}")
            LocationFindingReference.objects.create(location=loc, finding=self._loc_finding, status="Active")
            LocationProductReference.objects.create(location=loc, product=self._loc_product, status="Active")

    def _representative_requests(self) -> dict[str, str]:
        """OpenAPI GET path -> concrete request URL. Extend when a phase adds endpoints."""
        finding_id = Finding.objects.first().pk
        product_id = Product.objects.first().pk
        product_type_id = Product_Type.objects.first().pk
        user_id = self.admin.pk
        limit = f"limit={_ROW_FANOUT + 5}"
        return {
            "/findings": self.v3_url(f"findings?{limit}&expand=test.engagement,locations&include=counts"),
            "/findings/{finding_id}": self.v3_url(f"findings/{finding_id}?expand=test.engagement"),  # noqa: RUF027 -- OpenAPI path template key, not an f-string
            "/products": self.v3_url(f"products?{limit}&expand=product_type"),
            "/products/{product_id}": self.v3_url(f"products/{product_id}"),  # noqa: RUF027 -- OpenAPI path template key, not an f-string
            "/product_types": self.v3_url(f"product_types?{limit}"),
            "/product_types/{product_type_id}": self.v3_url(f"product_types/{product_type_id}"),  # noqa: RUF027 -- OpenAPI path template key, not an f-string
            "/users": self.v3_url(f"users?{limit}"),
            "/users/{user_id}": self.v3_url(f"users/{user_id}"),  # noqa: RUF027 -- OpenAPI path template key, not an f-string
            "/engagements": self.v3_url(f"engagements?{limit}"),
            "/engagements/{engagement_id}": self.v3_url(f"engagements/{Engagement.objects.first().pk}"),
            "/tests": self.v3_url(f"tests?{limit}"),
            "/tests/{test_id}": self.v3_url(f"tests/{Test.objects.first().pk}"),
            "/locations": self.v3_url(f"locations?{limit}"),
            "/locations/{location_id}": self.v3_url(f"locations/{Location.objects.order_by('pk').first().pk}"),
            "/findings/{finding_id}/locations": self.v3_url(f"findings/{self._loc_finding.pk}/locations?{limit}"),  # noqa: RUF027
            "/products/{product_id}/locations": self.v3_url(f"products/{self._loc_product.pk}/locations?{limit}"),  # noqa: RUF027
        }

    def _openapi_get_paths(self) -> set[str]:
        schema = api_v3.get_openapi_schema()
        # Schema paths carry the mount prefix (/api/v3-alpha/...); compare mount-relative.
        return {
            "/" + path.split(settings.API_V3_URL_PREFIX, 1)[-1].lstrip("/")
            for path, ops in schema["paths"].items()
            if "get" in ops
        }

    def test_no_n_plus_one_across_surface(self):
        requests = self._representative_requests()

        missing = self._openapi_get_paths() - set(requests)
        self.assertFalse(
            missing,
            f"GET endpoint(s) {sorted(missing)} have no representative request in the query "
            f"sweep — add one to _representative_requests() (this is deliberate: every new "
            f"endpoint must be query-profiled).",
        )

        captures = [capture_request(self.client, path, url) for path, url in requests.items()]
        _REPORT_PATH.write_text(format_report(captures, _THRESHOLD), encoding="utf-8")

        failures = []
        for cap in captures:
            self.assertEqual(cap.status_code, 200, f"{cap.label} -> {cap.status_code}")
            for shape, count in cap.repeated_shapes(_THRESHOLD):
                failures.append(f"{cap.label}: {count}x {shape[:160]}")
        self.assertFalse(
            failures,
            "N+1 signature detected (same query shape repeated within one request):\n"
            + "\n".join(failures)
            + f"\nFull report: {_REPORT_PATH}",
        )
