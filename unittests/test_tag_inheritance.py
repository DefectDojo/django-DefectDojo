"""
All tag inheritance tests in one place.

Covers:
- Pure unit tests for tags_signals.py routing and logic functions
- Integration tests for system-wide and per-product inheritance flags
- Endpoint tag inheritance (v2)
- Location tag inheritance including multi-product (v3)
- Import / reimport with inherited tags (API and UI)
"""

import logging
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.contrib.auth.models import User
from django.db import connection
from django.test import Client, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from dojo.importers.location_manager import LocationManager
from dojo.location.models import Location, LocationProductReference
from dojo.location.status import ProductLocationStatus
from dojo.models import Endpoint, Engagement, Finding, Product, Product_Type, Test, Test_Type
from dojo.tags.inheritance import (
    _sync_inherited_tags,  # noqa: PLC2701 -- private API tested directly
    get_products,
    is_tag_inheritance_enabled,
    propagate_tags_on_product_sync,
)
from dojo.tags.signals import auto_inherit_product_tags
from dojo.tools.locations import LocationData
from unittests.dojo_test_case import (
    DojoAPITestCase,
    DojoTestCase,
    get_unit_tests_scans_path,
    skip_unless_v2,
    skip_unless_v3,
    versioned_fixtures,
)

logger = logging.getLogger(__name__)

_finding_counter = 0


def _make_finding():
    global _finding_counter  # noqa: PLW0603
    _finding_counter += 1
    now = timezone.now()
    user, _ = User.objects.get_or_create(username="tag_inherit_test_user", defaults={"is_active": True})
    pt, _ = Product_Type.objects.get_or_create(name="Tag Inherit Test Type")
    product = Product.objects.create(name=f"Tag Inherit Product {_finding_counter}", description="test", prod_type=pt)
    eng = Engagement.objects.create(product=product, target_start=now, target_end=now)
    tt, _ = Test_Type.objects.get_or_create(name="Tag Inherit Test")
    test = Test.objects.create(engagement=eng, test_type=tt, target_start=now, target_end=now)
    return Finding.objects.create(test=test, title="Tag Inherit Finding", severity="Medium", reporter=user)


# ---------------------------------------------------------------------------
# Pure unit tests — no DB
# ---------------------------------------------------------------------------

class TestGetProducts(unittest.TestCase):

    """
    Unit tests for get_products() — the isinstance router that resolves any model instance to its owning Product(s).

    No DB needed. Uses MagicMock with __class__ overridden so isinstance() passes,
    then verifies the correct attribute chain is returned for each model type.
    """

    def _make(self, cls):
        obj = MagicMock()
        obj.__class__ = cls
        return obj

    def test_product_returns_self(self):
        obj = self._make(Product)
        self.assertEqual(get_products(obj), [obj])

    def test_endpoint_returns_product(self):
        obj = self._make(Endpoint)
        self.assertEqual(get_products(obj), [obj.product])

    def test_engagement_returns_product(self):
        obj = self._make(Engagement)
        self.assertEqual(get_products(obj), [obj.product])

    def test_test_returns_product_via_engagement(self):
        obj = self._make(Test)
        self.assertEqual(get_products(obj), [obj.engagement.product])

    def test_finding_returns_product_via_test_engagement(self):
        obj = self._make(Finding)
        self.assertEqual(get_products(obj), [obj.test.engagement.product])

    def test_location_delegates_to_all_related_products(self):
        obj = self._make(Location)
        obj.all_related_products.return_value = ["p1", "p2"]
        self.assertEqual(get_products(obj), ["p1", "p2"])

    def test_unknown_type_returns_empty(self):
        self.assertEqual(get_products(object()), [])


class TestInheritProductTags(unittest.TestCase):

    """
    Unit tests for inherit_product_tags() — the gate that decides whether inheritance should run at all.

    Returns True if either the system-wide setting or any product's per-product flag is enabled.
    Both dependencies (get_products and get_system_setting) are mocked so only the boolean
    priority logic is tested, not DB reads or isinstance routing.
    """

    def _make_product(self, *, per_product_flag):
        p = MagicMock()
        p.enable_product_tag_inheritance = per_product_flag
        return p

    @patch("dojo.tags.inheritance.get_system_setting", return_value=True)
    @patch("dojo.tags.inheritance.get_products")
    def test_system_setting_on_returns_true(self, mock_get_products, mock_setting):
        mock_get_products.return_value = [self._make_product(per_product_flag=False)]
        self.assertTrue(is_tag_inheritance_enabled(MagicMock()))

    @patch("dojo.tags.inheritance.get_system_setting", return_value=False)
    @patch("dojo.tags.inheritance.get_products")
    def test_per_product_flag_on_system_off_returns_true(self, mock_get_products, mock_setting):
        mock_get_products.return_value = [self._make_product(per_product_flag=True)]
        self.assertTrue(is_tag_inheritance_enabled(MagicMock()))

    @patch("dojo.tags.inheritance.get_system_setting", return_value=False)
    @patch("dojo.tags.inheritance.get_products")
    def test_both_off_returns_false(self, mock_get_products, mock_setting):
        mock_get_products.return_value = [self._make_product(per_product_flag=False)]
        self.assertFalse(is_tag_inheritance_enabled(MagicMock()))

    @patch("dojo.tags.inheritance.get_system_setting", return_value=False)
    @patch("dojo.tags.inheritance.get_products")
    def test_no_products_returns_false(self, mock_get_products, mock_setting):
        mock_get_products.return_value = []
        self.assertFalse(is_tag_inheritance_enabled(MagicMock()))

    @patch("dojo.tags.inheritance.get_system_setting", return_value=False)
    @patch("dojo.tags.inheritance.get_products")
    def test_none_entries_in_product_list_are_skipped(self, mock_get_products, mock_setting):
        mock_get_products.return_value = [None, self._make_product(per_product_flag=False)]
        self.assertFalse(is_tag_inheritance_enabled(MagicMock()))


class TestManageInheritedTagsDiff(unittest.TestCase):

    """
    Unit tests for _sync_inherited_tags() — the diff primitive.

    Verifies that the function:
      - Adds inherited tags that aren't yet recorded.
      - Removes inherited tags that no longer belong.
      - Re-adds inherited tags missing from instance.tags (sticky enforcement).
      - Does no work when target matches current state.
    """

    def _tag(self, name):
        t = MagicMock()
        t.name = name
        return t

    def _make_instance(self, inherited_names, tag_names):
        instance = MagicMock()
        # Skip the FakeTagRelatedManager branch so we exercise the diff path.
        instance.inherited_tags.__class__ = MagicMock
        instance.tags.__class__ = MagicMock
        instance.inherited_tags.all.return_value = [self._tag(n) for n in inherited_names]
        instance.tags.all.return_value = [self._tag(n) for n in tag_names]
        return instance

    def test_already_in_sync_no_writes(self):
        instance = self._make_instance(["alpha", "beta"], tag_names=["alpha", "beta"])
        _sync_inherited_tags(instance, ["alpha", "beta"])
        instance.inherited_tags.add.assert_not_called()
        instance.inherited_tags.remove.assert_not_called()
        instance.tags.add.assert_not_called()
        instance.tags.remove.assert_not_called()

    def test_target_adds_new_inherited(self):
        instance = self._make_instance(["old"], tag_names=["old", "user"])
        _sync_inherited_tags(instance, ["old", "new"])
        instance.inherited_tags.add.assert_called_once_with("new")
        instance.tags.add.assert_called_once_with("new")
        instance.inherited_tags.remove.assert_not_called()
        instance.tags.remove.assert_not_called()

    def test_target_removes_dropped_inherited(self):
        instance = self._make_instance(["alpha", "beta"], tag_names=["alpha", "beta", "user"])
        _sync_inherited_tags(instance, ["alpha"])
        instance.inherited_tags.remove.assert_called_once_with("beta")
        instance.tags.remove.assert_called_once_with("beta")
        instance.inherited_tags.add.assert_not_called()
        instance.tags.add.assert_not_called()

    def test_sticky_readds_missing_inherited(self):
        # inherited_tags already records "alpha", target is "alpha", but user
        # stripped it from tags via m2m_changed. Sticky enforcement re-adds it.
        instance = self._make_instance(["alpha"], tag_names=["user"])
        _sync_inherited_tags(instance, ["alpha"])
        instance.inherited_tags.add.assert_not_called()
        instance.inherited_tags.remove.assert_not_called()
        instance.tags.remove.assert_not_called()
        instance.tags.add.assert_called_once_with("alpha")


class TestInheritInstanceTagsEarlyExit(unittest.TestCase):

    """No-products case: auto_inherit_product_tags must short-circuit before touching the instance."""

    @patch("dojo.tags.signals.get_products_to_inherit_tags_from")
    def test_no_products_skips_write(self, mock_get):
        instance = MagicMock()
        mock_get.return_value = []
        auto_inherit_product_tags(instance)
        instance.inherit_tags.assert_not_called()
        instance.inherited_tags.add.assert_not_called()
        instance.tags.add.assert_not_called()


# ---------------------------------------------------------------------------
# Integration tests — inheritance disabled
# ---------------------------------------------------------------------------

@versioned_fixtures
class TestInheritanceDisabled(DojoTestCase):

    """
    Integration tests verifying that inheritance is a no-op when both flags are off.

    The existing suite always enabled inheritance. These tests confirm the negative path:
    product tags must not leak to child objects, and any tags already on a child must
    survive unmodified.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.system_settings(enable_product_tag_inheritance=False)

    def test_product_tags_do_not_reach_engagement_or_test(self):
        product = self.create_product("No Inherit", tags=["should-not-propagate"])
        engagement = self.create_engagement("Eng", product)
        test = self.create_test(engagement=engagement, scan_type="ZAP Scan")
        self.assertEqual(list(engagement.tags.all()), [])
        self.assertEqual(list(test.tags.all()), [])

    def test_own_tags_on_child_not_overwritten(self):
        product = self.create_product("No Inherit", tags=["product-tag"])
        engagement = self.create_engagement("Eng", product)
        engagement.tags.add("my-own-tag")
        self.assertEqual([t.name for t in engagement.tags.all()], ["my-own-tag"])


# ---------------------------------------------------------------------------
# Integration tests — per-product flag
# ---------------------------------------------------------------------------

@versioned_fixtures
class TestPerProductTagInheritance(DojoTestCase):

    """
    Integration tests for the per-product enable_product_tag_inheritance flag.

    The existing test suite only exercised the system-wide setting. These tests verify
    that a product with its own flag=True propagates tags even when the system setting is off,
    while products with flag=False do not — covering the branch in get_products_to_inherit_tags_from()
    that was previously untested.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.system_settings(enable_product_tag_inheritance=False)

    def test_per_product_flag_on_propagates_tags(self):
        product = self.create_product("Per-Product On", tags=["alpha", "beta"])
        product.enable_product_tag_inheritance = True
        product.save()
        engagement = self.create_engagement("Eng", product)
        tag_names = sorted(t.name for t in engagement.tags.all())
        self.assertEqual(tag_names, ["alpha", "beta"])

    def test_per_product_flag_off_no_propagation(self):
        product = self.create_product("Per-Product Off", tags=["alpha", "beta"])
        engagement = self.create_engagement("Eng", product)
        self.assertEqual(list(engagement.tags.all()), [])

    def test_mixed_products_only_flagged_product_propagates(self):
        p_inherit = self.create_product("Inheriting", tags=["inherit-me"])
        p_inherit.enable_product_tag_inheritance = True
        p_inherit.save()
        p_no = self.create_product("Not Inheriting", tags=["skip-me"])
        eng_with = self.create_engagement("Eng With", p_inherit)
        eng_without = self.create_engagement("Eng Without", p_no)
        self.assertEqual(sorted(t.name for t in eng_with.tags.all()), ["inherit-me"])
        self.assertEqual(list(eng_without.tags.all()), [])

    def test_finding_created_with_own_tag_keeps_it_and_inherits(self):
        """
        Regression test for #15092.

        Assigning tags to an unsaved finding and then saving it (the UI
        "add finding" flow: ``finding.tags = [...]; finding.save()``) must keep
        the user's own tags *and* merge the inherited product tags. Previously
        the inheritance post_save handler ran before tagulous persisted the
        pre-save tags and silently dropped them.
        """
        product = self.create_product("Inherit On Create", tags=["product-tag"])
        product.enable_product_tag_inheritance = True
        product.save()
        engagement = self.create_engagement("Eng", product)
        test = self.create_test(engagement=engagement, scan_type="ZAP Scan")

        finding = Finding(test=test, title="With own tag", severity="Medium", reporter=self.get_test_admin())
        finding.tags = ["my-own-tag"]
        finding.save()
        finding.refresh_from_db()

        self.assertEqual(sorted(t.name for t in finding.tags.all()), ["my-own-tag", "product-tag"])
        self.assertEqual([t.name for t in finding.inherited_tags.all()], ["product-tag"])

    def test_finding_created_without_own_tag_still_inherits(self):
        """A finding created with no tags must still receive the product's inherited tags (#15092 guard)."""
        product = self.create_product("Inherit No Own Tag", tags=["product-tag"])
        product.enable_product_tag_inheritance = True
        product.save()
        engagement = self.create_engagement("Eng", product)
        test = self.create_test(engagement=engagement, scan_type="ZAP Scan")

        finding = Finding(test=test, title="No own tag", severity="Medium", reporter=self.get_test_admin())
        finding.save()
        finding.refresh_from_db()

        self.assertEqual([t.name for t in finding.tags.all()], ["product-tag"])
        self.assertEqual([t.name for t in finding.inherited_tags.all()], ["product-tag"])


# ---------------------------------------------------------------------------
# Integration tests — endpoint inheritance (v2 only)
# ---------------------------------------------------------------------------

@skip_unless_v2
@versioned_fixtures
class TestEndpointTagInheritance(DojoTestCase):

    """
    Integration tests (v2 only) for Endpoint tag inheritance.

    get_products() handles Endpoint but it was never exercised by the existing suite.
    Verifies tags propagate on creation and that inherited tags are sticky
    (the make_inherited_tags_sticky signal re-adds them if removed).
    Skipped when V3_FEATURE_LOCATIONS is enabled — Endpoints are replaced by Locations in v3.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.system_settings(enable_product_tag_inheritance=True)
        self.product = self.create_product("Endpoint Tag Test", tags=["alpha", "beta"])

    def test_new_endpoint_inherits_product_tags(self):
        endpoint = Endpoint(host="test.example.com", product=self.product)
        endpoint.save()
        tag_names = sorted(t.name for t in endpoint.tags.all())
        self.assertEqual(tag_names, ["alpha", "beta"])

    def test_inherited_tag_cannot_be_removed_from_endpoint(self):
        endpoint = Endpoint(host="sticky.example.com", product=self.product)
        endpoint.save()
        before = sorted(t.name for t in endpoint.tags.all())
        endpoint.tags.remove("alpha")
        after = sorted(t.name for t in endpoint.tags.all())
        self.assertEqual(before, after)


# ---------------------------------------------------------------------------
# Integration tests — location inheritance (v3 only)
# ---------------------------------------------------------------------------

@skip_unless_v3
class TestTagInheritanceOnPersist(DojoTestCase):

    """
    Integration tests (v3 only) for tag inheritance via LocationManager.persist().

    Verifies that tags are applied during bulk location creation and that repeated
    persist() calls with unchanged data are no-ops (no spurious DB mutations).
    """

    def test_locations_inherit_product_tags(self):
        """Locations should inherit tags from their associated product after persist."""
        finding = _make_finding()
        product = finding.test.engagement.product
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

    def test_bulk_inherit_is_no_op_when_already_in_sync(self):
        """Calling persist() again with the same data should not re-inherit (no mutation queries)."""
        finding = _make_finding()
        product = finding.test.engagement.product
        product.enable_product_tag_inheritance = True
        product.save()
        product.tags.add("a", "b")

        loc_data = [LocationData(type="url", data={"url": "https://oss-nosync.example.com"})]
        mgr1 = LocationManager(product)
        mgr1.record_locations_for_finding(finding, loc_data)
        mgr1.persist()

        mgr2 = LocationManager(product)
        mgr2.record_locations_for_finding(finding, loc_data)
        with CaptureQueriesContext(connection) as ctx:
            mgr2.persist()

        mutation_queries = [q for q in ctx.captured_queries if q["sql"].startswith(("INSERT", "UPDATE"))]
        for q in mutation_queries:
            self.assertNotIn("inherited_tags", q["sql"].lower(), f"Unexpected inherited_tags mutation: {q['sql']}")

    def test_bulk_inherit_already_synced_is_constant_time(self):
        """Repeated persist() calls on already-synced locations fire no tag mutation queries."""
        finding = _make_finding()
        product = finding.test.engagement.product
        product.enable_product_tag_inheritance = True
        product.save()
        product.tags.add("p-tag-1", "p-tag-2")

        loc_data = [
            LocationData(type="url", data={"url": f"https://oss-sync-{i}.example.com"})
            for i in range(10)
        ]
        mgr1 = LocationManager(product)
        mgr1.record_locations_for_finding(finding, loc_data)
        mgr1.persist()

        mgr2 = LocationManager(product)
        mgr2.record_locations_for_finding(finding, loc_data)
        with CaptureQueriesContext(connection) as ctx:
            mgr2.persist()

        tag_through = Location.tags.through._meta.db_table
        inherited_through = Location.inherited_tags.through._meta.db_table
        for q in ctx.captured_queries:
            sql = q["sql"].lower()
            if sql.startswith(("insert", "update", "delete")):
                self.assertNotIn(tag_through.lower(), sql, f"Unexpected tags mutation: {q['sql']}")
                self.assertNotIn(inherited_through.lower(), sql, f"Unexpected inherited_tags mutation: {q['sql']}")


@skip_unless_v3
@versioned_fixtures
class TestLocationMultipleProductInheritance(DojoTestCase):

    """
    Integration tests (v3 only) for Location inheriting from multiple products.

    Unlike Engagement/Test/Finding which belong to exactly one product, a Location can be
    linked to many products via LocationProductReference. These tests verify that
    all_related_products() is used correctly and tags are merged from every linked product,
    and that the per-product flag filters correctly when the system setting is off.
    auto_inherit_product_tags() is called directly rather than relying on signal chaining.
    Skipped when V3_FEATURE_LOCATIONS is disabled.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.system_settings(enable_product_tag_inheritance=True)

    def test_location_inherits_from_multiple_products(self):
        from dojo.tags.signals import auto_inherit_product_tags  # noqa: PLC0415

        p1 = self.create_product("Product A", tags=["p1-tag"])
        p2 = self.create_product("Product B", tags=["p2-tag"])

        location = Location(location_type="url", location_value="https://multi.example.com")
        location.save()
        LocationProductReference.objects.create(
            location=location, product=p1, status=ProductLocationStatus.Active,
        )
        LocationProductReference.objects.create(
            location=location, product=p2, status=ProductLocationStatus.Active,
        )

        auto_inherit_product_tags(location)
        location.refresh_from_db()

        tag_names = sorted(t.name for t in location.tags.all())
        self.assertIn("p1-tag", tag_names)
        self.assertIn("p2-tag", tag_names)

    def test_location_inherits_only_from_flagged_product_when_system_off(self):
        from dojo.tags.signals import auto_inherit_product_tags  # noqa: PLC0415

        self.system_settings(enable_product_tag_inheritance=False)

        p_inherit = self.create_product("Flagged", tags=["yes-tag"])
        p_inherit.enable_product_tag_inheritance = True
        p_inherit.save()
        p_no = self.create_product("Unflagged", tags=["no-tag"])

        location = Location(location_type="url", location_value="https://mixed.example.com")
        location.save()
        LocationProductReference.objects.create(
            location=location, product=p_inherit, status=ProductLocationStatus.Active,
        )
        LocationProductReference.objects.create(
            location=location, product=p_no, status=ProductLocationStatus.Active,
        )

        auto_inherit_product_tags(location)
        location.refresh_from_db()

        tag_names = sorted(t.name for t in location.tags.all())
        self.assertIn("yes-tag", tag_names)
        self.assertNotIn("no-tag", tag_names)


# ---------------------------------------------------------------------------
# Integration tests — system-wide inheritance, non-import scenarios
# ---------------------------------------------------------------------------

@override_settings(CELERY_TASK_ALWAYS_EAGER=True)
@versioned_fixtures
class InheritedTagsTests(DojoAPITestCase):

    """Non-import tests for inherited tags functionality."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self, *args, **kwargs):
        super().setUp()
        self.login_as_admin()
        self.system_settings(enable_product_tag_inheritance=True)
        self.product = self.create_product("Inherited Tags Test", tags=["inherit", "these", "tags"])
        self.scans_path = get_unit_tests_scans_path("zap")
        self.zap_sample5_filename = self.scans_path / "5_zap_sample_one.xml"

    def _convert_instance_tags_to_list(self, instance) -> list:
        return [tag.name for tag in instance.tags.all()]

    def test_new_engagement_then_add_tag_to_engagement_then_remove_tag_to_engagement(self):
        # Create the engagement
        engagement = self.create_engagement("Inherited Tags Engagement", self.product)
        test = self.create_test(engagement=engagement, scan_type="ZAP Scan")
        # Check to see if tags match the product
        product_tags = self._convert_instance_tags_to_list(self.product)
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(engagement))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(test))
        # Add a tag on the engagement)
        engagement_tags_before_addition = self._convert_instance_tags_to_list(engagement)
        engagement.tags.add("engagement_only_tag")
        # Check to see that the update was successful
        self.assertEqual(["engagement_only_tag", *engagement_tags_before_addition], self._convert_instance_tags_to_list(engagement))
        # Check to see that tests were not impacted
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(test))
        # remove a tag on the engagement
        engagement_tags_before_removal = self._convert_instance_tags_to_list(engagement)
        engagement.tags.remove("engagement_only_tag")
        # Check to see that the update was successful
        engagement_tags_before_removal.remove("engagement_only_tag")
        self.assertEqual(engagement_tags_before_removal, self._convert_instance_tags_to_list(engagement))
        # Check to see that tests were not impacted
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(test))

    def test_new_engagement_then_remove_inherited_tag(self):
        # Create the engagement
        engagement = self.create_engagement("Inherited Tags Engagement", self.product)
        # Check to see if tags match the product
        product_tags = self._convert_instance_tags_to_list(self.product)
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(engagement))
        # Remove an inherited tag
        engagement_tags_before_removal = self._convert_instance_tags_to_list(engagement)
        engagement.tags.remove("inherit")
        # Check to see that the inherited tag could not be removed
        self.assertEqual(engagement_tags_before_removal, self._convert_instance_tags_to_list(engagement))


# ---------------------------------------------------------------------------
# Integration tests — import / reimport with inherited tags
# ---------------------------------------------------------------------------

class InheritedTagsImportMixin:

    """Mixin containing inherited tags import/reimport tests that can be run via API or UI."""

    def setUp(self):
        self.system_settings(enable_product_tag_inheritance=True)
        self.product = self.create_product("Inherited Tags Test", tags=["inherit", "these", "tags"])
        self.scans_path = get_unit_tests_scans_path("zap")
        self.zap_sample5_filename = self.scans_path / "5_zap_sample_one.xml"

    def _convert_instance_tags_to_list(self, instance) -> list:
        return [tag.name for tag in instance.tags.all()]

    def _import_and_return_objects(self, test_id=None, *, reimport=False, tags=None) -> dict:
        # Import some findings to create all objects
        engagement = self.create_engagement("Inherited Tags Engagement", self.product)
        if reimport:
            response = self.reimport_scan_with_params(test_id, self.zap_sample5_filename, tags=tags)
        else:
            response = self.import_scan_with_params(self.zap_sample5_filename, engagement=engagement.id, tags=tags)

        test_id = response["test"]
        test = Test.objects.get(id=test_id)
        finding = Finding.objects.filter(test=test).first()
        location = self._get_location(finding)
        return {
            "engagement": engagement,
            "location": location,
            "test": test,
            "finding": finding,
        }

    def _get_location(self, finding):
        # TODO: Delete this after the move to Locations
        if not settings.V3_FEATURE_LOCATIONS:
            return finding.endpoints.all().first()
        return finding.locations.all().first().location

    def test_import_without_tags(self):
        # Import some findings to create all objects
        objects = self._import_and_return_objects()
        # Check that the tags all match what the product has
        product_tags = self._convert_instance_tags_to_list(self.product)
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("engagement")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("location")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("test")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("finding")))

    def test_import_with_tags_then_reimport_with_different_tag(self):
        # Import some findings to create all objects
        objects = self._import_and_return_objects(tags=["import_tag"])
        # Check that the tags all match what the product has
        product_tags = self._convert_instance_tags_to_list(self.product)
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("engagement")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("location")))
        self.assertEqual(["import_tag", *product_tags], self._convert_instance_tags_to_list(objects.get("test")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("finding")))
        # Reimport now
        objects = self._import_and_return_objects(test_id=objects.get("test").id, reimport=True, tags=["reimport_tag"])
        # Check that the tags all match what the product has
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("engagement")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("location")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("finding")))
        # Make a copy of the list becase of the need for the lists to be exact (index for index)
        product_tags_plus_reimport_tag = product_tags.copy()
        product_tags_plus_reimport_tag.insert(1, "reimport_tag")
        self.assertEqual(product_tags_plus_reimport_tag, self._convert_instance_tags_to_list(objects.get("test")))

    def test_remove_tag_from_product_then_add_tag_to_product(self):
        # Import some findings to create all objects
        objects = self._import_and_return_objects()
        # Check that the tags all match what the product has
        product_tags = self._convert_instance_tags_to_list(self.product)
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("engagement")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("location")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("test")))
        self.assertEqual(product_tags, self._convert_instance_tags_to_list(objects.get("finding")))
        # Remove a tag from the product
        self.product.tags.remove("inherit")
        # This triggers an async function with celery that will fail, so run it manually here
        propagate_tags_on_product_sync(self.product)
        # Save the tags post removal
        product_tags_post_removal = self._convert_instance_tags_to_list(self.product)
        # Check that the tags all match what the product has
        self.assertEqual(product_tags_post_removal, self._convert_instance_tags_to_list(objects.get("engagement")))
        self.assertEqual(product_tags_post_removal, self._convert_instance_tags_to_list(objects.get("location")))
        self.assertEqual(product_tags_post_removal, self._convert_instance_tags_to_list(objects.get("test")))
        self.assertEqual(product_tags_post_removal, self._convert_instance_tags_to_list(objects.get("finding")))
        # Add a tag from the product
        self.product.tags.add("more", "tags!")
        # This triggers an async function with celery that will fail, so run it manually here
        propagate_tags_on_product_sync(self.product)
        # Save the tags post removal
        product_tags_post_addition = self._convert_instance_tags_to_list(self.product)
        # Check that the tags all match what the product has
        self.assertEqual(product_tags_post_addition, self._convert_instance_tags_to_list(objects.get("engagement")))
        self.assertEqual(product_tags_post_addition, self._convert_instance_tags_to_list(objects.get("location")))
        self.assertEqual(product_tags_post_addition, self._convert_instance_tags_to_list(objects.get("test")))
        self.assertEqual(product_tags_post_addition, self._convert_instance_tags_to_list(objects.get("finding")))


@override_settings(CELERY_TASK_ALWAYS_EAGER=True)
@versioned_fixtures
class InheritedTagsImportTestAPI(DojoAPITestCase, InheritedTagsImportMixin):

    """Test inherited tags during import/reimport via API."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.usercontactinfo.save()
        self.login_as_admin()
        settings.SECURE_SSL_REDIRECT = False
        InheritedTagsImportMixin.setUp(self)


@override_settings(CELERY_TASK_ALWAYS_EAGER=True)
@versioned_fixtures
class InheritedTagsImportTestUI(DojoAPITestCase, InheritedTagsImportMixin):

    """Test inherited tags during import/reimport via UI."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.usercontactinfo.save()
        self.login_as_admin()
        settings.SECURE_SSL_REDIRECT = False
        self.client_ui = Client()
        self.client_ui.force_login(self.get_test_admin())
        InheritedTagsImportMixin.setUp(self)

    def import_scan_with_params(self, filename, scan_type="ZAP Scan", engagement=1, minimum_severity="Low", *,
                                active=True, verified=False, tags=None, close_old_findings=False, **kwargs):
        """Override to use UI import instead of API."""
        with Path(filename).open(encoding="utf-8") as testfile:
            payload = {
                "minimum_severity": minimum_severity,
                "active": "force_to_true" if active else "force_to_false",
                "verified": "force_to_true" if verified else "force_to_false",
                "scan_type": scan_type,
                "file": testfile,
                "environment": 1,
                "close_old_findings": close_old_findings,
            }
            if tags is not None:
                # Tagulous form field expects comma-separated string
                payload["tags"] = ",".join(tags) if isinstance(tags, list) else tags

            response = self.client_ui.post(reverse("import_scan_results", args=(engagement,)), payload)
            self.assertEqual(302, response.status_code, response.content[:1000])
            test_id = int(response.url.split("/")[-1])
            return {"test": test_id}

    def reimport_scan_with_params(self, test_id, filename, scan_type="ZAP Scan", minimum_severity="Low", *,
                                  active=True, verified=False, tags=None, close_old_findings=True, **kwargs):
        """Override to use UI reimport instead of API."""
        with Path(filename).open(encoding="utf-8") as testfile:
            payload = {
                "minimum_severity": minimum_severity,
                "active": "force_to_true" if active else "force_to_false",
                "verified": "force_to_true" if verified else "force_to_false",
                "scan_type": scan_type,
                "file": testfile,
                "close_old_findings": close_old_findings,
            }
            if tags is not None:
                # Tagulous form field expects comma-separated string
                payload["tags"] = ",".join(tags) if isinstance(tags, list) else tags

            response = self.client_ui.post(reverse("re_import_scan_results", args=(test_id,)), payload)
            self.assertEqual(302, response.status_code, response.content[:1000])
            new_test_id = int(response.url.split("/")[-1])
            return {"test": new_test_id}
