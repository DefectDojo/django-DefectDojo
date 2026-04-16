from django.conf import settings
from django.test import TestCase
from django.utils import timezone

from dojo.location.models import Location
from dojo.models import Endpoint, Engagement, Finding, Product, Product_Type, Test, Test_Type
from dojo.tag_utils import bulk_add_tag_mapping, bulk_add_tags_to_instances, bulk_apply_parser_tags
from dojo.url.models import URL
from unittests.dojo_test_case import DojoAPITestCase, versioned_fixtures


class BulkTagUtilsTest(TestCase):
    LOCATION_CLASS = Location if settings.V3_FEATURE_LOCATIONS else Endpoint

    def setUp(self):
        # Tag model backing Endpoint.tags
        self.tag_model = self._get_tag_model()
        # Ensure endpoints have a product to satisfy tag inheritance signals
        self.product_type = Product_Type.objects.create(name="PT-Bulk-Base")
        self.product = Product.objects.create(name="Bulk Base Product", description="test", prod_type=self.product_type)

    def _get_tag_model(self):
        return self.LOCATION_CLASS.tags.tag_model

    def _make_location(self, hostname, product):
        # TODO: Delete this after the move to Locations
        if not settings.V3_FEATURE_LOCATIONS:
            return Endpoint.objects.create(product=product, host=hostname)
        url = URL.get_or_create_from_values(host=hostname)
        url.location.associate_with_product(product)
        return url.location

    def _make_locations(self, n):
        return [self._make_location(f"host-{i}.example.com", self.product) for i in range(n)]

    def test_bulk_add_tag_to_instances_basic(self):
        instances = self._make_locations(5)

        created_count = bulk_add_tags_to_instances(
            tag_or_tags="bulk-test",
            instances=instances,
        )

        self.assertEqual(created_count, 5)
        for instance in instances:
            instance.refresh_from_db()
            self.assertIn("bulk-test", [t.name for t in instance.tags.all()])

        tag = self.tag_model.objects.get(name="bulk-test")
        self.assertEqual(tag.count, 5)

    def test_bulk_add_tag_to_instances_with_existing(self):
        instances = self._make_locations(5)

        instances[0].tags.add("bulk-test")
        instances[1].tags.add("bulk-test")

        created_count = bulk_add_tags_to_instances(
            tag_or_tags="bulk-test",
            instances=instances,
        )

        self.assertEqual(created_count, 3)
        for instance in instances:
            instance.refresh_from_db()
            self.assertIn("bulk-test", [t.name for t in instance.tags.all()])

        tag = self.tag_model.objects.get(name="bulk-test")
        self.assertEqual(tag.count, 5)

    def test_bulk_add_tag_to_instances_empty_list(self):
        created_count = bulk_add_tags_to_instances(
            tag_or_tags="bulk-test",
            instances=[],
        )
        self.assertEqual(created_count, 0)
        self.assertEqual(self.tag_model.objects.filter(name="bulk-test").count(), 0)

    def test_bulk_add_tag_to_instances_with_queryset(self):
        instances = self._make_locations(5)
        queryset = self.LOCATION_CLASS.objects.all()

        created_count = bulk_add_tags_to_instances(
            tag_or_tags="bulk-test",
            instances=queryset,
        )
        self.assertEqual(created_count, 5)
        for instance in instances:
            instance.refresh_from_db()
            self.assertIn("bulk-test", [t.name for t in instance.tags.all()])

    def test_bulk_add_tag_to_instances_batching(self):
        instances = self._make_locations(25)

        created_count = bulk_add_tags_to_instances(
            tag_or_tags="bulk-test",
            instances=instances,
            batch_size=10,
        )

        self.assertEqual(created_count, 25)
        for instance in instances:
            instance.refresh_from_db()
            self.assertIn("bulk-test", [t.name for t in instance.tags.all()])

        tag = self.tag_model.objects.get(name="bulk-test")
        self.assertEqual(tag.count, 25)

    def test_bulk_add_clears_prefetch_cache_instances_reused(self):
        # Create instances and prefetch their tags into the Django prefetch cache
        created = self._make_locations(3)
        ids = [e.id for e in created]
        instances = list(self.LOCATION_CLASS.objects.filter(id__in=ids).prefetch_related("tags"))

        # Sanity: tags initially empty via prefetch cache
        for instance in instances:
            self.assertEqual(list(instance.tags.all()), [])

        # Bulk add tag using the same in-memory instances
        added = bulk_add_tags_to_instances(tag_or_tags="cache-test", instances=instances)
        self.assertEqual(added, 3)

        # Our bulk add method clears the prefetch cache so this should now reflect the DB state
        for instance in instances:
            names = [t.name for t in instance.tags.all()]
            self.assertIn("cache-test", names)

        # Tag count should reflect total relationships
        self.assertEqual(self.tag_model.objects.get(name="cache-test").count, 3)

    def test_bulk_add_tag_to_instances_case_insensitive(self):
        instances = self._make_locations(3)

        instances[0].tags.add("Bulk-Test")

        created_count = bulk_add_tags_to_instances(
            tag_or_tags="bulk-test",
            instances=instances,
        )

        self.assertEqual(created_count, 2)
        # With force_lowercase on our TagField, there should be one tag
        self.assertEqual(self.tag_model.objects.count(), 1)
        tag = self.tag_model.objects.first()
        self.assertEqual(tag.count, 3)

    def test_bulk_add_tag_to_instances_edit_string_multiple(self):
        instances = self._make_locations(4)

        created_count = bulk_add_tags_to_instances(
            tag_or_tags="alpha, beta",
            instances=instances,
        )

        self.assertEqual(created_count, 8)
        for instance in instances:
            instance.refresh_from_db()
            names = [t.name for t in instance.tags.all()]
            self.assertIn("alpha", names)
            self.assertIn("beta", names)

        self.assertEqual(self.tag_model.objects.get(name="alpha").count, 4)
        self.assertEqual(self.tag_model.objects.get(name="beta").count, 4)

    def test_bulk_add_tag_to_instances_iterable_strings(self):
        instances = self._make_locations(3)

        created_count = bulk_add_tags_to_instances(
            tag_or_tags=["one", "two"],
            instances=instances,
        )

        self.assertEqual(created_count, 6)
        for instance in instances:
            instance.refresh_from_db()
            names = [t.name for t in instance.tags.all()]
            self.assertIn("one", names)
            self.assertIn("two", names)

    def test_bulk_add_tag_to_instances_iterable_tag_objects(self):
        instances = self._make_locations(2)
        # Pre-create tag objects
        t1 = self.tag_model.objects.create(name="obj-a")
        t2 = self.tag_model.objects.create(name="obj-b")

        created_count = bulk_add_tags_to_instances(
            tag_or_tags=[t1, t2],
            instances=instances,
        )

        self.assertEqual(created_count, 4)
        for instance in instances:
            instance.refresh_from_db()
            names = [t.name for t in instance.tags.all()]
            self.assertIn("obj-a", names)
            self.assertIn("obj-b", names)

    def test_bulk_add_tag_to_instances_duplicates_ignored(self):
        instances = self._make_locations(3)

        created_count = bulk_add_tags_to_instances(
            tag_or_tags=["dup", "dup"],
            instances=instances,
        )

        # Only one unique tag applied
        self.assertEqual(created_count, 3)
        self.assertEqual(self.tag_model.objects.count(), 1)
        self.assertEqual(self.tag_model.objects.first().count, 3)

    def test_bulk_add_tag_to_product_rejected(self):
        # Arrange: create product with inheritance enabled and children
        pt = Product_Type.objects.create(name="PT")
        product = Product.objects.create(name="P1", description="test", prod_type=pt, enable_product_tag_inheritance=True)
        eng = Engagement.objects.create(name="E1", product=product, target_start=timezone.now(), target_end=timezone.now())
        tt = Test_Type.objects.create(name="Dummy")
        test = Test.objects.create(title="T1", engagement=eng, test_type=tt, target_start=timezone.now(), target_end=timezone.now())
        loc1 = self._make_location("p.example.com", product)
        loc2 = self._make_location("q.example.com", product)

        # Act & Assert: bulk util should reject Product instances
        with self.assertRaises(ValueError) as cm:
            _ = bulk_add_tags_to_instances(tag_or_tags="p-tag", instances=[product])
        self.assertIn("Product instances are not supported", str(cm.exception))

        # Ensure nothing was tagged as a side-effect
        product.refresh_from_db()
        self.assertNotIn("p-tag", [t.name for t in product.tags.all()])
        for child in (eng, test, loc1, loc2):
            child.refresh_from_db()
            self.assertNotIn("p-tag", [t.name for t in child.tags.all()])
            self.assertNotIn("p-tag", [t.name for t in child.inherited_tags.all()])

    def test_bulk_add_invalid_field_name(self):
        instances = self._make_locations(1)

        with self.assertRaises(ValueError) as cm:
            bulk_add_tags_to_instances(
                tag_or_tags="bulk-test",
                instances=[instances[0]],
                tag_field_name="nonexistent_field",
            )
        self.assertIn("does not have field", str(cm.exception))

    def get_tag_field_name(self):
        # TODO: Delete this after the move to Locations
        if not settings.V3_FEATURE_LOCATIONS:
            return "host"
        return "location_type"

    def test_bulk_add_non_tag_field(self):
        instances = self._make_locations(1)

        with self.assertRaises(ValueError) as cm:
            bulk_add_tags_to_instances(
                tag_or_tags="bulk-test",
                instances=[instances[0]],
                tag_field_name=self.get_tag_field_name(),
            )
        self.assertIn("is not a TagField", str(cm.exception))


class BulkTagMappingTest(TestCase):

    """Tests for bulk_add_tag_mapping — the multi-tag, ~5-query variant."""

    LOCATION_CLASS = Location if settings.V3_FEATURE_LOCATIONS else Endpoint

    def setUp(self):
        self.tag_model = self.LOCATION_CLASS.tags.tag_model
        self.product_type = Product_Type.objects.create(name="PT-Mapping")
        self.product = Product.objects.create(name="Mapping Product", description="test", prod_type=self.product_type)

    def _make_location(self, hostname):
        if not settings.V3_FEATURE_LOCATIONS:
            return Endpoint.objects.create(product=self.product, host=hostname)
        url = URL.get_or_create_from_values(host=hostname)
        url.location.associate_with_product(self.product)
        return url.location

    def _make_locations(self, n):
        return [self._make_location(f"map-host-{i}.example.com") for i in range(n)]

    def test_basic_different_tags_different_instances(self):
        a, b, c = self._make_locations(3)
        created = bulk_add_tag_mapping({"alpha": [a, b], "beta": [b, c], "gamma": [c]})

        self.assertEqual(created, 5)
        a.refresh_from_db()
        b.refresh_from_db()
        c.refresh_from_db()
        self.assertEqual([t.name for t in a.tags.all()], ["alpha"])
        self.assertCountEqual([t.name for t in b.tags.all()], ["alpha", "beta"])
        self.assertCountEqual([t.name for t in c.tags.all()], ["beta", "gamma"])

        self.assertEqual(self.tag_model.objects.get(name="alpha").count, 2)
        self.assertEqual(self.tag_model.objects.get(name="beta").count, 2)
        self.assertEqual(self.tag_model.objects.get(name="gamma").count, 1)

    def test_same_tag_across_all_instances(self):
        instances = self._make_locations(4)
        created = bulk_add_tag_mapping({"shared": instances})

        self.assertEqual(created, 4)
        self.assertEqual(self.tag_model.objects.get(name="shared").count, 4)

    def test_skips_existing_relationships(self):
        a, b, c = self._make_locations(3)
        a.tags.add("existing")
        b.tags.add("existing")

        created = bulk_add_tag_mapping({"existing": [a, b, c]})

        self.assertEqual(created, 1)
        self.assertEqual(self.tag_model.objects.get(name="existing").count, 3)

    def test_empty_dict_returns_zero(self):
        created = bulk_add_tag_mapping({})
        self.assertEqual(created, 0)

    def test_empty_instance_lists_returns_zero(self):
        created = bulk_add_tag_mapping({"tag-a": [], "tag-b": []})
        self.assertEqual(created, 0)
        self.assertEqual(self.tag_model.objects.filter(name__in=["tag-a", "tag-b"]).count(), 0)

    def test_case_insensitive_finds_existing_tag(self):
        # Pre-create tag in lowercase (simulating force_lowercase storage)
        instances = self._make_locations(2)
        instances[0].tags.add("mytag")

        # Requesting "MYTAG" should match the existing "mytag" object
        created = bulk_add_tag_mapping({"MYTAG": [instances[0], instances[1]]})

        self.assertEqual(created, 1)
        self.assertEqual(self.tag_model.objects.count(), 1)

    def test_creates_new_tags_that_dont_exist(self):
        instances = self._make_locations(2)
        created = bulk_add_tag_mapping({"brand-new-a": [instances[0]], "brand-new-b": [instances[1]]})

        self.assertEqual(created, 2)
        self.assertTrue(self.tag_model.objects.filter(name="brand-new-a").exists())
        self.assertTrue(self.tag_model.objects.filter(name="brand-new-b").exists())

    def test_clears_prefetch_cache(self):
        instances = list(self.LOCATION_CLASS.objects.filter(
            pk__in=[loc.pk for loc in self._make_locations(2)],
        ).prefetch_related("tags"))

        for inst in instances:
            self.assertEqual(list(inst.tags.all()), [])

        bulk_add_tag_mapping({"cache-map": instances})

        for inst in instances:
            self.assertIn("cache-map", [t.name for t in inst.tags.all()])

    def test_product_rejected(self):
        pt = Product_Type.objects.create(name="PT-Reject")
        product = Product.objects.create(name="P-Reject", description="x", prod_type=pt)
        with self.assertRaises(ValueError, msg="Product instances are not supported"):
            bulk_add_tag_mapping({"tag": [product]})

    def test_batching_creates_all_relationships(self):
        instances = self._make_locations(15)
        created = bulk_add_tag_mapping({"batch-tag": instances}, batch_size=4)

        self.assertEqual(created, 15)
        self.assertEqual(self.tag_model.objects.get(name="batch-tag").count, 15)


class BulkApplyParserTagsTest(TestCase):

    """Tests for bulk_apply_parser_tags — the import-loop accumulator path."""

    def setUp(self):
        self.tag_model = Finding.tags.tag_model
        pt = Product_Type.objects.create(name="PT-Parser")
        product = Product.objects.create(name="Parser Product", description="x", prod_type=pt)
        engagement = Engagement.objects.create(
            name="E-Parser", product=product,
            target_start=timezone.now(), target_end=timezone.now(),
        )
        tt = Test_Type.objects.create(name="Parser Test Type")
        test = Test.objects.create(
            title="T-Parser", engagement=engagement, test_type=tt,
            target_start=timezone.now(), target_end=timezone.now(),
        )
        self.test = test

    def _make_finding(self, title):
        return Finding.objects.create(title=title, severity="Low", test=self.test)

    def test_applies_tags_correctly(self):
        f1 = self._make_finding("F1")
        f2 = self._make_finding("F2")
        f3 = self._make_finding("F3")

        bulk_apply_parser_tags([
            (f1, ["network", "web"]),
            (f2, ["network"]),
            (f3, ["pci"]),
        ])

        f1.refresh_from_db()
        f2.refresh_from_db()
        f3.refresh_from_db()
        self.assertCountEqual([t.name for t in f1.tags.all()], ["network", "web"])
        self.assertCountEqual([t.name for t in f2.tags.all()], ["network"])
        self.assertCountEqual([t.name for t in f3.tags.all()], ["pci"])

        self.assertEqual(self.tag_model.objects.get(name="network").count, 2)
        self.assertEqual(self.tag_model.objects.get(name="web").count, 1)
        self.assertEqual(self.tag_model.objects.get(name="pci").count, 1)

    def test_empty_list_is_noop(self):
        bulk_apply_parser_tags([])
        self.assertEqual(self.tag_model.objects.count(), 0)

    def test_filters_empty_tag_strings(self):
        f = self._make_finding("F-empty")
        bulk_apply_parser_tags([(f, ["", "valid", ""])])
        f.refresh_from_db()
        self.assertEqual([t.name for t in f.tags.all()], ["valid"])

    def test_dynamic_tags_many_unique_values(self):
        # Simulate a parser that emits one unique tag per finding (e.g. resource name)
        findings = [self._make_finding(f"F-dyn-{i}") for i in range(20)]
        pairs = [(f, [f"resource-{i}"]) for i, f in enumerate(findings)]
        bulk_apply_parser_tags(pairs)

        for i, f in enumerate(findings):
            f.refresh_from_db()
            self.assertEqual([t.name for t in f.tags.all()], [f"resource-{i}"])

        self.assertEqual(self.tag_model.objects.count(), 20)


@versioned_fixtures
class BulkTagUtilsInheritanceTest(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.system_settings(enable_product_tag_inheritance=True)
        self.product_type = Product_Type.objects.create(name="PT-Bulk-Inherit")
        self.product = Product.objects.create(name="Bulk Inherit Product", description="test", prod_type=self.product_type, enable_product_tag_inheritance=True, tags=["inherit", "these", "tags"])

    def _tags_list(self, obj):
        return [t.name for t in obj.tags.all()]

    def _inherited_tags_list(self, obj):
        return [t.name for t in obj.inherited_tags.all()]

    def test_bulk_add_tags_to_findings_does_not_affect_inheritance(self):
        # Arrange: build a minimal tree with engagement/test and two findings
        engagement = Engagement.objects.create(name="E-Bulk", product=self.product, target_start=timezone.now(), target_end=timezone.now())
        # Ensure a Test_Type exists for this scan_type in fixtures; use a common one
        scan_type = "ZAP Scan"
        test = Test.objects.create(title="T-Bulk", engagement=engagement, test_type=Test_Type.objects.get(name=scan_type), target_start=timezone.now(), target_end=timezone.now())

        finding_a = Finding.objects.create(title="F-A", severity="Low", test=test)
        finding_b = Finding.objects.create(title="F-B", severity="Low", test=test)

        # Assert preconditions: inherited tags equal product tags, and tags include inherited
        product_tags = self._tags_list(self.product)
        self.assertEqual(product_tags, self._inherited_tags_list(finding_a))
        self.assertEqual(product_tags, self._inherited_tags_list(finding_b))
        self.assertEqual(product_tags, self._tags_list(finding_a))
        self.assertEqual(product_tags, self._tags_list(finding_b))

        # Act: bulk add a custom tag to both findings
        created = bulk_add_tags_to_instances(tag_or_tags="custom-bulk", instances=[finding_a, finding_b])
        self.assertEqual(created, 2)

        # Reload and verify: inherited tags unchanged; new tag present only in main tags
        for f in (finding_a, finding_b):
            f.refresh_from_db()
            self.assertEqual(product_tags, self._inherited_tags_list(f))
            tags = self._tags_list(f)
            self.assertIn("custom-bulk", tags)
            # Ensure inherited tags did not get polluted by the new tag
            self.assertNotIn("custom-bulk", self._inherited_tags_list(f))
