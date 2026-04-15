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
from dojo.models import Engagement, Finding, Product, Product_Type, Test, Test_Type
from dojo.tools.locations import LocationAssociationData, LocationData
from dojo.url.models import URL
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3

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

    def test_product_only_locations(self):
        pt, _ = Product_Type.objects.get_or_create(name="Refs Test Type")
        product = Product.objects.create(name="Refs Product Only", description="test", prod_type=pt)

        mgr = LocationManager(product)
        mgr._product_locations.extend([_make_url("oss-product-only.example.com")])
        mgr.persist()

        self.assertTrue(LocationProductReference.objects.filter(product=product).exists())
        self.assertFalse(LocationFindingReference.objects.exists())


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
# Tag inheritance after bulk persist
# ---------------------------------------------------------------------------
@skip_unless_v3
class TestTagInheritanceOnPersist(DojoTestCase):

    def test_locations_inherit_product_tags(self):
        """Locations should inherit tags from their associated product after persist."""
        finding = _make_finding()
        product = finding.test.engagement.product
        # Enable tag inheritance at the product level and add some product tags
        product.enable_product_tag_inheritance = True
        product.save()
        product.tags.add("inherit", "tags", "these")

        loc_data = [LocationData(type="url", data={"url": "https://oss-tag-inherit.example.com"})]
        mgr = LocationManager(product)
        mgr.record_locations_for_finding(finding, loc_data)
        mgr.persist()

        loc = Location.objects.get(url__host="oss-tag-inherit.example.com")
        inherited = sorted(t.name for t in loc.inherited_tags.all())
        self.assertEqual(inherited, ["inherit", "tags", "these"])
