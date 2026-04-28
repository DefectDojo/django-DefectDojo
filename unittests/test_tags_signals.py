import unittest
from unittest.mock import MagicMock, patch

from dojo.location.models import Location, LocationProductReference
from dojo.location.status import ProductLocationStatus
from dojo.models import Endpoint, Engagement, Finding, Product, Test
from dojo.tags_signals import (
    get_products,
    inherit_product_tags,
    propagate_inheritance,
)
from unittests.dojo_test_case import DojoTestCase, skip_unless_v2, skip_unless_v3, versioned_fixtures


class TestGetProducts(unittest.TestCase):
    """Unit tests for get_products() — the isinstance router that resolves any model instance to its owning Product(s).

    No DB needed. Uses MagicMock with __class__ overridden so isinstance() passes,
    then verifies the correct attribute chain is returned for each model type.
    """

    def _make(self, cls):
        obj = MagicMock()
        obj.__class__ = cls
        return obj

    def test_product_returns_self(self):
        obj = self._make(Product)
        assert get_products(obj) == [obj]

    def test_endpoint_returns_product(self):
        obj = self._make(Endpoint)
        assert get_products(obj) == [obj.product]

    def test_engagement_returns_product(self):
        obj = self._make(Engagement)
        assert get_products(obj) == [obj.product]

    def test_test_returns_product_via_engagement(self):
        obj = self._make(Test)
        assert get_products(obj) == [obj.engagement.product]

    def test_finding_returns_product_via_test_engagement(self):
        obj = self._make(Finding)
        assert get_products(obj) == [obj.test.engagement.product]

    def test_location_delegates_to_all_related_products(self):
        obj = self._make(Location)
        obj.all_related_products.return_value = ["p1", "p2"]
        assert get_products(obj) == ["p1", "p2"]

    def test_unknown_type_returns_empty(self):
        assert get_products(object()) == []


class TestInheritProductTags(unittest.TestCase):
    """Unit tests for inherit_product_tags() — the gate that decides whether inheritance should run at all.

    Returns True if either the system-wide setting or any product's per-product flag is enabled.
    Both dependencies (get_products and get_system_setting) are mocked so only the boolean
    priority logic is tested, not DB reads or isinstance routing.
    """

    def _make_product(self, per_product_flag):
        p = MagicMock()
        p.enable_product_tag_inheritance = per_product_flag
        return p

    @patch("dojo.tags_signals.get_system_setting", return_value=True)
    @patch("dojo.tags_signals.get_products")
    def test_system_setting_on_returns_true(self, mock_get_products, _):
        mock_get_products.return_value = [self._make_product(False)]
        assert inherit_product_tags(MagicMock()) is True

    @patch("dojo.tags_signals.get_system_setting", return_value=False)
    @patch("dojo.tags_signals.get_products")
    def test_per_product_flag_on_system_off_returns_true(self, mock_get_products, _):
        mock_get_products.return_value = [self._make_product(True)]
        assert inherit_product_tags(MagicMock()) is True

    @patch("dojo.tags_signals.get_system_setting", return_value=False)
    @patch("dojo.tags_signals.get_products")
    def test_both_off_returns_false(self, mock_get_products, _):
        mock_get_products.return_value = [self._make_product(False)]
        assert inherit_product_tags(MagicMock()) is False

    @patch("dojo.tags_signals.get_system_setting", return_value=False)
    @patch("dojo.tags_signals.get_products")
    def test_no_products_returns_false(self, mock_get_products, _):
        mock_get_products.return_value = []
        assert inherit_product_tags(MagicMock()) is False

    @patch("dojo.tags_signals.get_system_setting", return_value=False)
    @patch("dojo.tags_signals.get_products")
    def test_none_entries_in_product_list_are_skipped(self, mock_get_products, _):
        mock_get_products.return_value = [None, self._make_product(False)]
        assert inherit_product_tags(MagicMock()) is False


class TestPropagateInheritanceEarlyExit(unittest.TestCase):
    """Unit tests for propagate_inheritance() — the optimization guard that skips redundant DB writes.

    Returns False ("nothing to do") only when BOTH conditions hold:
      1. product tags match what is stored in instance.inherited_tags (already recorded)
      2. those tags are already present in the instance's full tag_list (already applied)
    If either condition is false, returns True and the caller proceeds to write tags.
    get_products_to_inherit_tags_from and instance.inherited_tags.all() are mocked
    to isolate the boolean logic from DB access.
    """

    def _tag(self, name):
        t = MagicMock()
        t.name = name
        return t

    def _make_instance(self, inherited_names):
        instance = MagicMock()
        instance.inherited_tags.all.return_value = [self._tag(n) for n in inherited_names]
        return instance

    def _make_product(self, tag_names):
        product = MagicMock()
        product.tags.all.return_value = [self._tag(n) for n in tag_names]
        return product

    @patch("dojo.tags_signals.get_products_to_inherit_tags_from")
    def test_already_in_sync_returns_false(self, mock_get):
        """inherited_tags matches product tags and all present in tag_list → skip."""
        instance = self._make_instance(["alpha", "beta"])
        mock_get.return_value = [self._make_product(["alpha", "beta"])]
        assert propagate_inheritance(instance, tag_list=["alpha", "beta"]) is False

    @patch("dojo.tags_signals.get_products_to_inherit_tags_from")
    def test_product_tags_changed_returns_true(self, mock_get):
        """Stored inherited_tags differ from current product tags → must propagate."""
        instance = self._make_instance(["old"])
        mock_get.return_value = [self._make_product(["new"])]
        assert propagate_inheritance(instance, tag_list=["old", "new"]) is True

    @patch("dojo.tags_signals.get_products_to_inherit_tags_from")
    def test_tags_not_yet_applied_to_instance_returns_true(self, mock_get):
        """inherited_tags already correct but not yet reflected in tag_list → must propagate."""
        instance = self._make_instance(["alpha"])
        mock_get.return_value = [self._make_product(["alpha"])]
        assert propagate_inheritance(instance, tag_list=[]) is True

    @patch("dojo.tags_signals.get_products_to_inherit_tags_from")
    def test_no_products_no_inherited_tags_returns_false(self, mock_get):
        """No products, no inherited tags, empty tag_list → already in sync, skip."""
        instance = self._make_instance([])
        mock_get.return_value = []
        assert propagate_inheritance(instance, tag_list=[]) is False


@versioned_fixtures
class TestPerProductTagInheritance(DojoTestCase):
    """Integration tests for the per-product enable_product_tag_inheritance flag.

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


@versioned_fixtures
class TestInheritanceDisabled(DojoTestCase):
    """Integration tests verifying that inheritance is a no-op when both flags are off.

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


@skip_unless_v2
@versioned_fixtures
class TestEndpointTagInheritance(DojoTestCase):
    """Integration tests (v2 only) for Endpoint tag inheritance.

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


@skip_unless_v3
@versioned_fixtures
class TestLocationMultipleProductInheritance(DojoTestCase):
    """Integration tests (v3 only) for Location inheriting from multiple products.

    Unlike Engagement/Test/Finding which belong to exactly one product, a Location can be
    linked to many products via LocationProductReference. These tests verify that
    all_related_products() is used correctly and tags are merged from every linked product,
    and that the per-product flag filters correctly when the system setting is off.
    inherit_instance_tags() is called directly rather than relying on signal chaining.
    Skipped when V3_FEATURE_LOCATIONS is disabled.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.system_settings(enable_product_tag_inheritance=True)

    def test_location_inherits_from_multiple_products(self):
        from dojo.tags_signals import inherit_instance_tags  # noqa: PLC0415

        p1 = self.create_product("Product A", tags=["p1-tag"])
        p2 = self.create_product("Product B", tags=["p2-tag"])

        location = Location(location_type="url", location_value="https://multi.example.com")
        location.save()
        LocationProductReference.objects.create(
            location=location, product=p1, status=ProductLocationStatus.Active
        )
        LocationProductReference.objects.create(
            location=location, product=p2, status=ProductLocationStatus.Active
        )

        inherit_instance_tags(location)
        location.refresh_from_db()

        tag_names = sorted(t.name for t in location.tags.all())
        self.assertIn("p1-tag", tag_names)
        self.assertIn("p2-tag", tag_names)

    def test_location_inherits_only_from_flagged_product_when_system_off(self):
        from dojo.tags_signals import inherit_instance_tags  # noqa: PLC0415

        self.system_settings(enable_product_tag_inheritance=False)

        p_inherit = self.create_product("Flagged", tags=["yes-tag"])
        p_inherit.enable_product_tag_inheritance = True
        p_inherit.save()
        p_no = self.create_product("Unflagged", tags=["no-tag"])

        location = Location(location_type="url", location_value="https://mixed.example.com")
        location.save()
        LocationProductReference.objects.create(
            location=location, product=p_inherit, status=ProductLocationStatus.Active
        )
        LocationProductReference.objects.create(
            location=location, product=p_no, status=ProductLocationStatus.Active
        )

        inherit_instance_tags(location)
        location.refresh_from_db()

        tag_names = sorted(t.name for t in location.tags.all())
        self.assertIn("yes-tag", tag_names)
        self.assertNotIn("no-tag", tag_names)
