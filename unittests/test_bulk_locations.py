"""
Tests for bulk location creation and association (open-source, URL-only).

Covers:
- AbstractLocation.bulk_get_or_create (on URL)
- LocationManager._bulk_get_or_create_locations (URL-only)
- LocationManager.record_locations_for_finding + persist (accumulator pattern)
- Query efficiency
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from dojo.importers.location_manager import LocationManager
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.models import Engagement, Finding, Product, Product_Type, Test, Test_Type
from dojo.tools.locations import LocationAssociationData, LocationData
from dojo.url.models import URL
from unittests.dojo_test_case import DojoTestCase, skip_unless_v2, skip_unless_v3

User = get_user_model()


def _make_url(host, path=""):
    url = URL(protocol="https", host=host, path=path)
    url.clean()
    return url


_finding_counter = 0


def _make_finding():
    global _finding_counter  # noqa: PLW0603
    _finding_counter += 1
    now = timezone.now()
    user, _ = User.objects.get_or_create(username="bulk_test_user", defaults={"is_active": True})
    pt, _ = Product_Type.objects.get_or_create(name="Bulk Test Type")
    product = Product.objects.create(name=f"Bulk Test Product {_finding_counter}", description="test", prod_type=pt)
    eng = Engagement.objects.create(product=product, target_start=now, target_end=now)
    tt, _ = Test_Type.objects.get_or_create(name="Bulk Test")
    test = Test.objects.create(engagement=eng, test_type=tt, target_start=now, target_end=now)
    return Finding.objects.create(test=test, title="Bulk Test Finding", severity="Medium", reporter=user)


# ---------------------------------------------------------------------------
# AbstractLocation.bulk_get_or_create (URL)
# ---------------------------------------------------------------------------
@skip_unless_v3
class TestBulkGetOrCreateURL(DojoTestCase):

    def test_all_new(self):
        urls = [_make_url(f"oss-new-{i}.example.com") for i in range(5)]
        saved = URL.bulk_get_or_create(urls)

        self.assertEqual(len(saved), 5)
        self.assertTrue(all(s.pk is not None for s in saved))
        self.assertTrue(all(s.location_id is not None for s in saved))
        self.assertEqual(URL.objects.filter(pk__in=[s.pk for s in saved]).count(), 5)

    def test_all_existing(self):
        originals = [URL.get_or_create_from_object(_make_url(f"oss-existing-{i}.example.com")) for i in range(3)]

        urls = [_make_url(f"oss-existing-{i}.example.com") for i in range(3)]
        saved = URL.bulk_get_or_create(urls)

        self.assertEqual(len(saved), 3)
        self.assertEqual({s.pk for s in saved}, {o.pk for o in originals})

    def test_mixed_new_and_existing(self):
        existing = URL.get_or_create_from_object(_make_url("oss-mixed-existing.example.com"))

        urls = [
            _make_url("oss-mixed-existing.example.com"),
            _make_url("oss-mixed-new.example.com"),
        ]
        saved = URL.bulk_get_or_create(urls)

        self.assertEqual(len(saved), 2)
        self.assertEqual(saved[0].pk, existing.pk)
        self.assertIsNotNone(saved[1].pk)

    def test_duplicates_in_input(self):
        urls = [
            _make_url("oss-dupe.example.com"),
            _make_url("oss-dupe.example.com"),
            _make_url("oss-unique.example.com"),
        ]
        saved = URL.bulk_get_or_create(urls)

        self.assertEqual(len(saved), 3)
        self.assertEqual(saved[0].pk, saved[1].pk)
        self.assertNotEqual(saved[2].pk, saved[0].pk)
        self.assertEqual(URL.objects.filter(host__in=["oss-dupe.example.com", "oss-unique.example.com"]).count(), 2)

    def test_preserves_association_data_on_new(self):
        url = _make_url("oss-assoc-new.example.com")
        url._association_data = LocationAssociationData(
            relationship_type="owned_by",
            relationship_data={"file_path": "/src/main.py"},
        )

        saved = URL.bulk_get_or_create([url])

        self.assertEqual(saved[0].get_association_data().relationship_type, "owned_by")

    def test_copies_association_data_to_existing(self):
        URL.get_or_create_from_object(_make_url("oss-assoc-existing.example.com"))

        url = _make_url("oss-assoc-existing.example.com")
        url._association_data = LocationAssociationData(relationship_type="used_by")

        saved = URL.bulk_get_or_create([url])

        self.assertEqual(saved[0].get_association_data().relationship_type, "used_by")

    def test_empty_input(self):
        self.assertEqual(URL.bulk_get_or_create([]), [])

    def test_parent_location_created(self):
        saved = URL.bulk_get_or_create([_make_url("oss-parent.example.com")])

        loc = Location.objects.get(pk=saved[0].location_id)
        self.assertEqual(loc.location_type, "url")
        self.assertIn("oss-parent.example.com", loc.location_value)

    def test_transaction_atomicity(self):
        initial_count = Location.objects.count()
        urls = [_make_url("oss-atomic.example.com")]

        with patch.object(URL.objects, "bulk_create", side_effect=Exception("boom")), \
             self.assertRaisesMessage(Exception, "boom"):
            URL.bulk_get_or_create(urls)

        self.assertEqual(Location.objects.count(), initial_count)


# ---------------------------------------------------------------------------
# LocationManager._bulk_get_or_create_locations (URL-only)
# ---------------------------------------------------------------------------
@skip_unless_v3
class TestBulkGetOrCreateLocations(DojoTestCase):

    def test_supported_location_types_includes_url(self):
        supported = LocationManager.get_supported_location_types()
        self.assertIn("url", supported)
        self.assertIs(supported["url"], URL)

    def test_url_only(self):
        urls = [_make_url("oss-loc-mgr.example.com")]
        saved = LocationManager._bulk_get_or_create_locations(urls)

        self.assertEqual(len(saved), 1)
        self.assertIsInstance(saved[0], URL)

    def test_handles_cleaned_location_data(self):
        loc_data = LocationData(type="url", data={"url": "https://oss-from-data.example.com/api"})
        cleaned = LocationManager.clean_unsaved_locations([loc_data])
        saved = LocationManager._bulk_get_or_create_locations(cleaned)

        self.assertEqual(len(saved), 1)
        self.assertIsInstance(saved[0], URL)
        self.assertEqual(saved[0].host, "oss-from-data.example.com")

    def test_empty_input(self):
        self.assertEqual(LocationManager._bulk_get_or_create_locations([]), [])


# ---------------------------------------------------------------------------
# LocationManager.persist — ref creation details
# ---------------------------------------------------------------------------
@skip_unless_v3
class TestPersistRefCreation(DojoTestCase):

    def test_uses_association_data(self):
        finding = _make_finding()
        product = finding.test.engagement.product
        url = _make_url("oss-refs-assoc.example.com")
        url._association_data = LocationAssociationData(
            relationship_type="owned_by",
            relationship_data={"file_path": "/app/main.py"},
        )

        mgr = LocationManager(product)
        mgr.record_locations_for_finding(finding, [url])
        mgr.persist()

        ref = LocationFindingReference.objects.get(finding=finding)
        self.assertEqual(ref.relationship, "owned_by")
        self.assertEqual(ref.relationship_data, {"file_path": "/app/main.py"})


# ---------------------------------------------------------------------------
# End-to-end: record + persist
# ---------------------------------------------------------------------------
@skip_unless_v3
class TestRecordAndPersist(DojoTestCase):

    def test_full_pipeline(self):
        finding = _make_finding()
        product = finding.test.engagement.product

        loc_data = [
            LocationData(type="url", data={"url": "https://oss-e2e-1.example.com/api"}),
            LocationData(type="url", data={"url": "https://oss-e2e-2.example.com/api"}),
        ]

        mgr = LocationManager(product)
        mgr.record_locations_for_finding(finding, loc_data)
        mgr.persist()

        self.assertEqual(LocationFindingReference.objects.filter(finding=finding).count(), 2)
        self.assertEqual(LocationProductReference.objects.filter(product=product).count(), 2)

    def test_empty_locations(self):
        finding = _make_finding()
        product = finding.test.engagement.product

        mgr = LocationManager(product)
        mgr.record_locations_for_finding(finding, [])
        mgr.persist()

        self.assertEqual(LocationFindingReference.objects.filter(finding=finding).count(), 0)

    def test_idempotent(self):
        finding = _make_finding()
        product = finding.test.engagement.product
        loc_data = [LocationData(type="url", data={"url": "https://oss-idempotent.example.com"})]

        mgr = LocationManager(product)
        mgr.record_locations_for_finding(finding, loc_data)
        mgr.persist()
        mgr.record_locations_for_finding(finding, loc_data)
        mgr.persist()

        self.assertEqual(LocationFindingReference.objects.filter(finding=finding).count(), 1)

    def test_multiple_findings_single_persist(self):
        finding1 = _make_finding()
        product = finding1.test.engagement.product
        # Create second finding on the same product/engagement/test
        finding2 = Finding.objects.create(
            test=finding1.test, title="Bulk Test Finding 2", severity="High", reporter=finding1.reporter,
        )

        mgr = LocationManager(product)
        mgr.record_locations_for_finding(finding1, [
            LocationData(type="url", data={"url": "https://oss-multi-1.example.com"}),
        ])
        mgr.record_locations_for_finding(finding2, [
            LocationData(type="url", data={"url": "https://oss-multi-2.example.com"}),
        ])
        mgr.persist()

        self.assertEqual(LocationFindingReference.objects.filter(finding=finding1).count(), 1)
        self.assertEqual(LocationFindingReference.objects.filter(finding=finding2).count(), 1)
        self.assertEqual(LocationProductReference.objects.filter(product=product).count(), 2)

    def test_locations_are_cleaned_during_persist(self):
        """
        Verify that locations go through clean() normalization when persisted.

        URL.clean() normalizes protocol/host to lowercase and sets default ports.
        If clean isn't called, the raw input values would be stored as-is.
        """
        finding = _make_finding()
        product = finding.test.engagement.product

        # Create a URL with uppercase protocol and host — clean() should normalize these
        loc_data = [LocationData(type="url", data={
            "protocol": "HTTPS",
            "host": "UPPERCASE.EXAMPLE.COM",
            "path": "api/v1",
        })]
        mgr = LocationManager(product)
        mgr.record_locations_for_finding(finding, loc_data)
        mgr.persist()

        saved_url = URL.objects.get(host="uppercase.example.com")
        # Protocol should be lowercased
        self.assertEqual(saved_url.protocol, "https")
        # Host should be lowercased
        self.assertEqual(saved_url.host, "uppercase.example.com")
        # Default HTTPS port should be set
        self.assertEqual(saved_url.port, 443)


# ---------------------------------------------------------------------------
# EndpointManager: verify clean is called during record_for_finding
# ---------------------------------------------------------------------------
@skip_unless_v2
class TestEndpointCleanOnRecord(DojoTestCase):

    def test_endpoints_are_cleaned_during_record_for_finding(self):
        """
        Verify that EndpointManager.record_for_finding() runs clean() on endpoints.

        Endpoint.clean() validates format (not normalize case). An endpoint with
        an invalid protocol should trigger a warning log but still be recorded
        (DefectDojo stores broken endpoints with a warning). An endpoint with a
        valid protocol should pass through clean() without error.
        """
        # Keep imports here for reasy removal of this entire test in the future, once endpoints is gone
        from dojo.importers.endpoint_manager import EndpointManager  # noqa: PLC0415
        from dojo.models import Endpoint  # noqa: PLC0415

        pt, _ = Product_Type.objects.get_or_create(name="EP Clean Test Type")
        product = Product.objects.create(name="EP Clean Test Product", description="t", prod_type=pt)

        mgr = EndpointManager(product)

        finding = _make_finding()
        # Valid endpoint + one with empty protocol (clean sets it to None)
        ep_valid = Endpoint(protocol="https", host="good.example.com")
        ep_empty_proto = Endpoint(protocol="", host="empty-proto.example.com")
        finding.unsaved_endpoints = [ep_valid, ep_empty_proto]

        mgr.record_for_finding(finding)

        # clean() should have set empty protocol to None
        self.assertEqual(ep_valid.protocol, "https")
        self.assertIsNone(ep_empty_proto.protocol)


# ---------------------------------------------------------------------------
# Query efficiency
# ---------------------------------------------------------------------------
@skip_unless_v3
class TestBulkQueryEfficiency(DojoTestCase):

    def test_bulk_fewer_queries_than_locations(self):
        urls = [_make_url(f"oss-perf-{i}.example.com") for i in range(50)]

        with CaptureQueriesContext(connection) as ctx:
            URL.bulk_get_or_create(urls)

        # Expected: ~3 queries (SELECT existing, INSERT parents, INSERT subtypes)
        self.assertLess(len(ctx.captured_queries), 10)


# ---------------------------------------------------------------------------
# Status update query efficiency
# ---------------------------------------------------------------------------
@skip_unless_v3
class TestStatusUpdateQueryEfficiency(DojoTestCase):

    """
    Verify that persist() flushes status updates with a bounded number of queries,
    regardless of how many findings were recorded (not O(n)).
    """

    def _setup_findings_with_mitigated_refs(self, count: int):
        """Create `count` findings in a single product, each with a mitigated LocationFindingReference."""
        # Single product for all findings
        first_finding = _make_finding()
        product = first_finding.test.engagement.product
        test = first_finding.test
        reporter = first_finding.reporter

        findings = [first_finding]
        findings.extend(
            Finding.objects.create(
                test=test, title=f"Status Test Finding {i}", severity="Medium", reporter=reporter,
            )
            for i in range(count - 1)
        )

        # Create one mitigated LocationFindingReference per finding
        for i, finding in enumerate(findings):
            saved = URL.bulk_get_or_create([_make_url(f"oss-status-{i}.example.com")])
            LocationFindingReference.objects.create(
                location=saved[0].location,
                finding=finding,
                status=FindingLocationStatus.Mitigated,
            )
        return findings, product

    def test_reactivate_for_many_findings_is_bulk(self):
        findings, product = self._setup_findings_with_mitigated_refs(count=20)
        mgr = LocationManager(product)
        for finding in findings:
            mgr.record_reactivations_for_finding(finding)

        with CaptureQueriesContext(connection) as ctx:
            mgr.persist()

        # Expected: 1 SELECT (gather ref IDs) + 1 UPDATE (reactivate)
        #         + 1 SELECT (affected location_ids) + 1 SELECT (still-active check) + up to 1 UPDATE (product refs)
        self.assertLess(len(ctx.captured_queries), 8, ctx.captured_queries)

    def test_update_location_status_for_many_findings_is_bulk(self):
        findings, product = self._setup_findings_with_mitigated_refs(count=20)
        reporter = findings[0].reporter
        mgr = LocationManager(product)

        # Simulate reimport "matched finding" flow: new finding with no unsaved locations => mitigate all
        for finding in findings:
            new_finding = Finding(title=finding.title, severity=finding.severity, test=finding.test, is_mitigated=True)
            new_finding.unsaved_locations = []
            mgr.update_location_status(finding, new_finding, reporter)

        with CaptureQueriesContext(connection) as ctx:
            mgr.persist()

        # Expected: 1 SELECT (partial-status fetch) + 1 UPDATE (mitigate)
        #         + 1 SELECT (affected location_ids) + 1 SELECT (still-active check) + up to 1 UPDATE (product refs)
        self.assertLess(len(ctx.captured_queries), 8, ctx.captured_queries)

    def test_partial_status_update_reactivates_matching_mitigates_rest(self):
        """
        When a reimported finding is NOT mitigated, locations still present in
        the report should be reactivated, and locations absent from the report
        should be mitigated.
        """
        finding = _make_finding()
        product = finding.test.engagement.product

        # Create three locations, all currently mitigated on this finding
        url_kept = _make_url("kept.example.com")
        url_also_kept = _make_url("also-kept.example.com")
        url_gone = _make_url("gone.example.com")
        saved = URL.bulk_get_or_create([url_kept, url_also_kept, url_gone])

        refs = [
            LocationFindingReference.objects.create(
                location=loc.location,
                finding=finding,
                status=FindingLocationStatus.Mitigated,
            )
            for loc in saved
        ]

        # Simulate a reimport where the new finding is active and only has two of the three locations
        new_finding = Finding(
            title=finding.title, severity=finding.severity,
            test=finding.test, is_mitigated=False,
        )
        new_finding.unsaved_locations = [
            LocationData(type="url", data={"url": "https://kept.example.com"}),
            LocationData(type="url", data={"url": "https://also-kept.example.com"}),
        ]

        mgr = LocationManager(product)
        mgr.update_location_status(finding, new_finding, finding.reporter)
        mgr.persist()

        # Refresh from DB
        for ref in refs:
            ref.refresh_from_db()

        # The two locations still in the report should be reactivated
        self.assertEqual(refs[0].status, FindingLocationStatus.Active)
        self.assertEqual(refs[1].status, FindingLocationStatus.Active)
        # The location no longer in the report should be mitigated
        self.assertEqual(refs[2].status, FindingLocationStatus.Mitigated)

    def test_product_ref_mitigated_when_all_finding_refs_mitigated(self):
        """When all finding refs for a location are mitigated, the product ref should become mitigated."""
        finding = _make_finding()
        product = finding.test.engagement.product

        url = _make_url("product-status-test.example.com")
        saved = URL.bulk_get_or_create([url])
        loc = saved[0]

        # Create active finding ref and active product ref
        LocationFindingReference.objects.create(
            location=loc.location, finding=finding, status=FindingLocationStatus.Active,
        )
        product_ref = LocationProductReference.objects.create(
            location=loc.location, product=product, status=ProductLocationStatus.Active,
        )

        # Mitigate the finding
        mgr = LocationManager(product)
        mgr.record_mitigations_for_finding(finding, finding.reporter)
        mgr.persist()

        product_ref.refresh_from_db()
        self.assertEqual(product_ref.status, ProductLocationStatus.Mitigated)

    def test_product_ref_stays_active_when_some_finding_refs_still_active(self):
        """When at least one finding ref is active, the product ref should stay active."""
        finding1 = _make_finding()
        product = finding1.test.engagement.product
        finding2 = Finding.objects.create(
            test=finding1.test, title="Second Finding", severity="Medium", reporter=finding1.reporter,
        )

        url = _make_url("shared-location.example.com")
        saved = URL.bulk_get_or_create([url])
        loc = saved[0]

        # Two findings share the same location, both active
        LocationFindingReference.objects.create(
            location=loc.location, finding=finding1, status=FindingLocationStatus.Active,
        )
        LocationFindingReference.objects.create(
            location=loc.location, finding=finding2, status=FindingLocationStatus.Active,
        )
        product_ref = LocationProductReference.objects.create(
            location=loc.location, product=product, status=ProductLocationStatus.Active,
        )

        # Mitigate only the first finding — second is still active
        mgr = LocationManager(product)
        mgr.record_mitigations_for_finding(finding1, finding1.reporter)
        mgr.persist()

        product_ref.refresh_from_db()
        self.assertEqual(product_ref.status, ProductLocationStatus.Active)

    def test_product_ref_reactivated_when_finding_ref_reactivated(self):
        """When a finding ref is reactivated, the product ref should become active."""
        finding = _make_finding()
        product = finding.test.engagement.product

        url = _make_url("reactivate-product.example.com")
        saved = URL.bulk_get_or_create([url])
        loc = saved[0]

        # Start with everything mitigated
        LocationFindingReference.objects.create(
            location=loc.location, finding=finding, status=FindingLocationStatus.Mitigated,
        )
        product_ref = LocationProductReference.objects.create(
            location=loc.location, product=product, status=ProductLocationStatus.Mitigated,
        )

        # Reactivate the finding
        mgr = LocationManager(product)
        mgr.record_reactivations_for_finding(finding)
        mgr.persist()

        product_ref.refresh_from_db()
        self.assertEqual(product_ref.status, ProductLocationStatus.Active)
