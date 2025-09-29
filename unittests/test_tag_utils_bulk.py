from django.test import TestCase

from dojo.models import Endpoint
from dojo.tag_utils import bulk_add_tags_to_instances


class BulkTagUtilsTest(TestCase):
    def setUp(self):
        # Tag model backing Endpoint.tags
        self.tag_model = Endpoint.tags.tag_model

    def _make_endpoints(self, n):
        return [Endpoint.objects.create(host=f"host-{i}.example.com") for i in range(n)]

    def test_bulk_add_tag_to_instances_basic(self):
        instances = self._make_endpoints(5)

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
        instances = self._make_endpoints(5)

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
        instances = self._make_endpoints(5)
        queryset = Endpoint.objects.all()

        created_count = bulk_add_tags_to_instances(
            tag_or_tags="bulk-test",
            instances=queryset,
        )
        self.assertEqual(created_count, 5)
        for instance in instances:
            instance.refresh_from_db()
            self.assertIn("bulk-test", [t.name for t in instance.tags.all()])

    def test_bulk_add_tag_to_instances_batching(self):
        instances = self._make_endpoints(25)

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

    def test_bulk_add_tag_to_instances_case_insensitive(self):
        instances = self._make_endpoints(3)

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
        instances = self._make_endpoints(4)

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
        instances = self._make_endpoints(3)

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
        instances = self._make_endpoints(2)
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
        instances = self._make_endpoints(3)

        created_count = bulk_add_tags_to_instances(
            tag_or_tags=["dup", "dup"],
            instances=instances,
        )

        # Only one unique tag applied
        self.assertEqual(created_count, 3)
        self.assertEqual(self.tag_model.objects.count(), 1)
        self.assertEqual(self.tag_model.objects.first().count, 3)

    def test_bulk_add_invalid_field_name(self):
        instances = self._make_endpoints(1)

        with self.assertRaises(ValueError) as cm:
            bulk_add_tags_to_instances(
                tag_or_tags="bulk-test",
                instances=[instances[0]],
                tag_field_name="nonexistent_field",
            )
        self.assertIn("does not have field", str(cm.exception))

    def test_bulk_add_non_tag_field(self):
        instances = self._make_endpoints(1)

        with self.assertRaises(ValueError) as cm:
            bulk_add_tags_to_instances(
                tag_or_tags="bulk-test",
                instances=[instances[0]],
                tag_field_name="host",
            )
        self.assertIn("is not a TagField", str(cm.exception))
