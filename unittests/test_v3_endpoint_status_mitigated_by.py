"""
``/api/v2/endpoint_status/?mitigated_by=`` under Locations takes a user id, as the legacy filter did.

Regression: with Locations on, the compatibility filter looked the value up with ``auditor__iexact``,
a text lookup on a foreign key, so every ``?mitigated_by=`` request answered 500 (``FieldError:
Unsupported lookup 'iexact' for ForeignKey``). The legacy ``Endpoint_Status`` filter was the
foreign key's own filter: a user id, an unknown id answered 400. The serializer's ``mitigated_by``
field also read ``auditor.id``, which loaded each mitigated row's user, one query per row.
"""

from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.location.models import LocationFindingReference
from dojo.location.status import FindingLocationStatus
from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type
from dojo.url.models import URL

from .dojo_test_case import DojoTestCase, skip_unless_v3
from .test_rest_framework import BASE_API_URL


def _url_location(host):
    url = URL(protocol="https", host=host, path="login")
    url.clean()
    return URL.bulk_get_or_create([url])[0].location


@skip_unless_v3
@override_settings(SECURE_SSL_REDIRECT=False)
class V3EndpointStatusMitigatedByTests(DojoTestCase):

    def setUp(self):
        super().setUp()
        self.product = Product.objects.create(
            name="status_mitigated_by_product", description="x", prod_type=Product_Type.objects.create(name="status_mitigated_by_pt"),
        )
        self.test_type = Test_Type.objects.get_or_create(name="status_mitigated_by_scan")[0]
        self.admin = Dojo_User.objects.create(username="status_mitigated_by_admin", is_active=True, is_staff=True, is_superuser=True)
        self.alice = Dojo_User.objects.create(username="status_mitigated_by_alice", is_active=True)
        self.bob = Dojo_User.objects.create(username="status_mitigated_by_bob", is_active=True)
        token, _ = Token.objects.get_or_create(user=self.admin)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        self.by_alice = self._status("by_alice", FindingLocationStatus.Mitigated, self.alice)
        self.by_bob = self._status("by_bob", FindingLocationStatus.Mitigated, self.bob)
        # Alice audited this one too, but it is not mitigated, so it is not "mitigated by" her.
        self.risk_accepted_by_alice = self._status("risk_accepted_by_alice", FindingLocationStatus.RiskAccepted, self.alice)
        self.active = self._status("active", FindingLocationStatus.Active, None)

    def _status(self, name, status, auditor):
        title = f"status_mitigated_by_{name}"
        engagement = Engagement.objects.create(name=f"{title} eng", product=self.product, target_start=timezone.now(), target_end=timezone.now())
        test = Test.objects.create(engagement=engagement, test_type=self.test_type, target_start=timezone.now(), target_end=timezone.now())
        finding = Finding.objects.create(test=test, title=title, description="x", severity="High", numerical_severity="S1", active=True, verified=True, reporter=self.admin)
        return LocationFindingReference.objects.create(
            location=_url_location(f"{name.replace('_', '-')}.status-mitigated-by.example.com"),
            finding=finding,
            status=status,
            auditor=auditor,
            audit_time=timezone.now() if auditor else None,
        )

    def _get(self, **params):
        return self.client.get(f"{BASE_API_URL}/endpoint_status/", {"limit": 100, **params}, format="json")

    def _ids(self, **params):
        response = self._get(**params)
        self.assertEqual(response.status_code, 200, response.content)
        return sorted(row["id"] for row in response.json()["results"])

    def test_filters_the_mitigated_statuses_by_the_users_id(self):
        self.assertEqual(self._ids(mitigated_by=self.alice.id), [self.by_alice.id])
        self.assertEqual(self._ids(mitigated_by=self.bob.id), [self.by_bob.id])

    def test_a_user_who_mitigated_nothing_matches_nothing(self):
        self.assertEqual(self._ids(mitigated_by=self.admin.id), [])

    def test_combines_with_the_other_filters(self):
        self.assertEqual(self._ids(mitigated_by=self.alice.id, finding=self.by_alice.finding_id), [self.by_alice.id])
        self.assertEqual(self._ids(mitigated_by=self.alice.id, finding=self.by_bob.finding_id), [])

    def test_an_unknown_user_or_a_username_is_a_400_as_on_the_legacy_filter(self):
        for value in (999999, self.alice.username):
            response = self._get(mitigated_by=value)
            self.assertEqual(response.status_code, 400, f"mitigated_by={value!r}: {response.content}")
            self.assertIn("mitigated_by", response.json())

    def test_the_field_names_the_mitigating_user_only_while_mitigated(self):
        rows = {row["id"]: row for row in self._get().json()["results"]}
        self.assertEqual(rows[self.by_alice.id]["mitigated_by"], self.alice.id)
        self.assertEqual(rows[self.by_bob.id]["mitigated_by"], self.bob.id)
        self.assertIsNone(rows[self.risk_accepted_by_alice.id]["mitigated_by"])
        self.assertIsNone(rows[self.active.id]["mitigated_by"])

    def test_the_list_costs_the_same_queries_for_more_mitigated_rows(self):
        def count():
            with CaptureQueriesContext(connection) as captured:
                response = self._get()
            self.assertEqual(response.status_code, 200, response.content)
            return len(captured.captured_queries), len(response.json()["results"])

        count()  # warm the per-request caches, so the comparison counts rows only
        before, rows_before = count()
        for n in range(4):
            self._status(f"more_{n}", FindingLocationStatus.Mitigated, self.bob if n % 2 else self.alice)
        after, rows_after = count()
        self.assertEqual(rows_after, rows_before + 4)
        self.assertEqual(after, before, "the mitigated_by field must not query per row")
