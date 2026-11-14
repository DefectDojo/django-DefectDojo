"""
Regression: a finding write carrying its endpoints cost queries per endpoint.

A client that reads a finding and writes the whole body back sends the finding's ``endpoints`` with it. The
field resolved each id with its own query, and with Locations on the update deleted every location reference
of the finding and created it again (a dozen queries per reference), which also reset each reference's status,
audit and test. A write of about a hundred endpoints ran more than two thousand queries.

These tests pin the fix: the field resolves the list with one query (with DRF's errors for an id it cannot
resolve), and a write leaves the references it submits again as they are, so its query count does not grow
with the number of endpoints.
"""

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.timezone import now
from rest_framework import serializers
from rest_framework.test import APIClient

from dojo.finding.api.serializer import BulkPrimaryKeyRelatedField
from dojo.location.models import LocationFindingReference
from dojo.location.status import FindingLocationStatus
from dojo.models import (
    Endpoint,
    Endpoint_Status,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)
from dojo.url.models import URL

from .dojo_test_case import skip_unless_v2, skip_unless_v3


class _BulkSerializer(serializers.Serializer):
    types = BulkPrimaryKeyRelatedField(many=True, queryset=Test_Type.objects.all())


class _StockSerializer(serializers.Serializer):
    types = serializers.PrimaryKeyRelatedField(many=True, queryset=Test_Type.objects.all())


class TestBulkPrimaryKeyRelatedField(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.types = [Test_Type.objects.create(name=f"bulk-pk-field-{idx}") for idx in range(5)]

    def test_resolves_the_whole_list_with_one_query(self):
        ids = [test_type.pk for test_type in self.types]
        submitted = [*ids, str(ids[0])]
        serializer = _BulkSerializer(data={"types": submitted})
        with CaptureQueriesContext(connection) as ctx:
            self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(len(ctx.captured_queries), 1, [q["sql"] for q in ctx.captured_queries])
        self.assertEqual([obj.pk for obj in serializer.validated_data["types"]], [*ids, ids[0]])

    def test_an_id_it_cannot_resolve_answers_with_drfs_error(self):
        missing = max(test_type.pk for test_type in self.types) + 1000
        first = self.types[0].pk
        for submitted in ([first, missing], [first, "abc"], [first, True], [first, None], "abc", [], [first, 1.5]):
            with self.subTest(submitted=submitted):
                bulk, stock = _BulkSerializer(data={"types": submitted}), _StockSerializer(data={"types": submitted})
                self.assertEqual(bulk.is_valid(), stock.is_valid())
                self.assertEqual(bulk.errors, stock.errors)

    def test_without_many_it_is_drfs_field(self):
        field = BulkPrimaryKeyRelatedField(queryset=Test_Type.objects.all())
        self.assertEqual(field.to_internal_value(self.types[1].pk), self.types[1])
        with self.assertRaises(serializers.ValidationError):
            field.to_internal_value(self.types[1].pk + 1000)


class _FindingWriteScaffold:

    """A superuser and a product to hang findings on (fixture-free)."""

    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(
            username="endpoints-write-admin",
            password="endpoints-write-not-a-real-password",  # noqa: S106 -- test-only account
            is_superuser=True,
            is_staff=True,
        )
        product_type = Product_Type.objects.create(name="endpoints-write-pt")
        cls.product = Product.objects.create(prod_type=product_type, name="endpoints-write", description="d")
        engagement = Engagement.objects.create(product=cls.product, target_start=now(), target_end=now())
        test_type, _ = Test_Type.objects.get_or_create(name="endpoints-write-scan")
        cls.test = Test.objects.create(
            engagement=engagement, test_type=test_type, target_start=now(), target_end=now(),
        )

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.sequence = 0

    def new_finding(self):
        self.sequence += 1
        return Finding.objects.create(
            test=self.test, title=f"endpoints write {self.sequence}", severity="High", numerical_severity="S1",
            description="d", active=True, verified=False, reporter=self.user,
        )

    def patch_endpoints(self, finding, ids):
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.patch(
                reverse("finding-detail", args=(finding.pk,)), {"endpoints": ids}, format="json",
            )
        self.assertEqual(response.status_code, 200, response.content[:500])
        return len(ctx.captured_queries)

    def assert_echo_is_flat(self):
        counts = {}
        for size in (2, 6):
            finding = self.new_finding()
            for idx in range(size):
                self.link(finding, idx)
            # A first write fills per-process caches the measured one would otherwise pay for.
            self.patch_endpoints(finding, self.ids(finding))
            counts[size] = self.patch_endpoints(finding, self.ids(finding))
        self.assertEqual(counts[2], counts[6], f"query counts by endpoint count: {counts}")


@skip_unless_v3
@override_settings(SECURE_SSL_REDIRECT=False)
class TestFindingEndpointsWriteLocations(_FindingWriteScaffold, TestCase):

    def link(self, finding, idx):
        location = URL.get_or_create_from_values(
            protocol="https", host=f"f{finding.pk}-{idx}.endpoints-write.example.com", path="x",
        ).location
        return location.associate_with_finding(finding)

    def ids(self, finding):
        return sorted(LocationFindingReference.objects.filter(finding=finding).values_list("pk", flat=True))

    def rows(self, finding):
        return sorted(
            LocationFindingReference.objects.filter(finding=finding).values_list(
                "pk", "location_id", "test_id", "status", "auditor_id", "audit_time", "created",
            ),
        )

    def test_an_echoed_write_does_not_scale_with_its_endpoints(self):
        self.assert_echo_is_flat()

    def test_an_echoed_write_leaves_each_reference_as_it_was(self):
        finding = self.new_finding()
        for idx in range(3):
            self.link(finding, idx)
        LocationFindingReference.objects.filter(pk=self.ids(finding)[0]).update(
            status=FindingLocationStatus.Mitigated, auditor=self.user, audit_time=now(),
        )
        before = self.rows(finding)
        self.patch_endpoints(finding, self.ids(finding))
        self.assertEqual(self.rows(finding), before)

    def test_a_write_drops_the_left_out_and_links_the_new(self):
        finding, other = self.new_finding(), self.new_finding()
        kept, dropped = self.link(finding, 0), self.link(finding, 1)
        theirs = self.link(other, 0)
        # A reference the write submits again keeps its row, status and audit: it is not reset to the finding's status.
        LocationFindingReference.objects.filter(pk=kept.pk).update(
            status=FindingLocationStatus.Mitigated, auditor=self.user, audit_time=now(),
        )
        kept_row = [row for row in self.rows(finding) if row[0] == kept.pk]
        self.patch_endpoints(finding, [kept.pk, theirs.pk])
        rows = self.rows(finding)
        self.assertEqual(sorted(row[1] for row in rows), sorted([kept.location_id, theirs.location_id]))
        self.assertEqual([row for row in rows if row[0] == kept.pk], kept_row)
        self.assertEqual(kept_row[0][3:5], (FindingLocationStatus.Mitigated, self.user.pk))
        self.assertFalse(LocationFindingReference.objects.filter(pk=dropped.pk).exists())
        added = LocationFindingReference.objects.get(finding=finding, location_id=theirs.location_id)
        self.assertEqual((added.test_id, added.status), (finding.test_id, FindingLocationStatus.Active))
        # The other finding's own reference is not touched.
        self.assertTrue(LocationFindingReference.objects.filter(pk=theirs.pk, finding=other).exists())


@skip_unless_v2
@override_settings(SECURE_SSL_REDIRECT=False)
class TestFindingEndpointsWriteLegacy(_FindingWriteScaffold, TestCase):

    def link(self, finding, idx):
        endpoint = Endpoint.objects.create(
            protocol="https", host=f"f{finding.pk}-{idx}.endpoints-write.example.com", product=self.product,
        )
        finding.endpoints.add(endpoint)
        return endpoint

    def ids(self, finding):
        return sorted(finding.endpoints.values_list("pk", flat=True))

    def test_an_echoed_write_does_not_scale_with_its_endpoints(self):
        self.assert_echo_is_flat()

    def test_an_echoed_write_leaves_each_status_as_it_was(self):
        finding = self.new_finding()
        for idx in range(3):
            self.link(finding, idx)
        statuses = Endpoint_Status.objects.filter(finding=finding)
        statuses.filter(pk=statuses.order_by("pk").first().pk).update(mitigated=True, mitigated_by=self.user)
        fields = ("pk", "endpoint_id", "mitigated", "mitigated_by_id", "date")
        before = sorted(statuses.values_list(*fields))
        self.patch_endpoints(finding, self.ids(finding))
        self.assertEqual(sorted(statuses.values_list(*fields)), before)
