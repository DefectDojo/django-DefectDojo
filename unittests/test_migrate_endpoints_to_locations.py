from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import TestCase, override_settings

from dojo.location.models import Location
from dojo.models import Endpoint, Product, Product_Type
from dojo.tags.utils import bulk_add_tag_mapping
from dojo.url.models import URL


@override_settings(V3_FEATURE_LOCATIONS=True)
class MigrateEndpointsToLocationsTest(TestCase):
    def setUp(self):
        product_type = Product_Type.objects.create(name="Endpoint migration product type")
        self.product = Product.objects.create(
            name="Endpoint migration product",
            description="Test product",
            prod_type=product_type,
        )

    def _make_endpoint(self, host, tags):
        with Endpoint.allow_endpoint_init():
            endpoint = Endpoint.objects.create(
                protocol="https",
                host=host,
                product=self.product,
            )
        endpoint.tags.add(*tags)
        return endpoint

    def test_endpoint_tags_are_copied_in_deduplicated_batches(self):
        # The first two legacy endpoints intentionally resolve to one Location.
        # The batch accumulator must not create or count that relationship twice.
        # Seed the Product tag before enabling propagation so setup does not
        # dispatch an unrelated asynchronous inheritance task.
        self.product.tags.add("product-inherited")
        self.product.enable_product_tag_inheritance = True
        self.product.save(update_fields=["enable_product_tag_inheritance"])
        self._make_endpoint("shared.example.com", ["shared", "secondary"])
        self._make_endpoint("shared.example.com", ["shared"])
        self._make_endpoint("unique.example.com", ["shared"])

        with patch(
            "dojo.management.commands.migrate_endpoints_to_locations.bulk_add_tag_mapping",
            wraps=bulk_add_tag_mapping,
        ) as bulk_add:
            call_command(
                "migrate_endpoints_to_locations",
                batch_size=2,
                progress_every=100,
                stdout=StringIO(),
            )

        self.assertEqual(bulk_add.call_count, 2)
        first_mapping = bulk_add.call_args_list[0].args[0]
        self.assertEqual(len(first_mapping["shared"]), 1)

        shared_location = URL.objects.get(host="shared.example.com").location
        unique_location = URL.objects.get(host="unique.example.com").location
        self.assertCountEqual(
            [tag.name for tag in shared_location.tags.all()],
            ["shared", "secondary", "product-inherited"],
        )
        self.assertCountEqual(
            [tag.name for tag in unique_location.tags.all()],
            ["shared", "product-inherited"],
        )
        self.assertEqual(
            [tag.name for tag in shared_location.inherited_tags.all()],
            ["product-inherited"],
        )
        self.assertEqual(
            [tag.name for tag in unique_location.inherited_tags.all()],
            ["product-inherited"],
        )

        tag_model = Location.tags.tag_model
        self.assertEqual(tag_model.objects.get(name="shared").count, 2)
        self.assertEqual(tag_model.objects.get(name="secondary").count, 1)
        self.assertEqual(tag_model.objects.get(name="product-inherited").count, 2)

        # The management command is designed to be safely rerunnable after a
        # partial migration. Existing relationships and Tagulous counts must
        # remain unchanged on a second pass.
        call_command(
            "migrate_endpoints_to_locations",
            batch_size=2,
            progress_every=100,
            stdout=StringIO(),
        )

        self.assertEqual(Location.tags.through.objects.count(), 5)
        self.assertEqual(Location.inherited_tags.through.objects.count(), 2)
        self.assertEqual(tag_model.objects.get(name="shared").count, 2)
        self.assertEqual(tag_model.objects.get(name="secondary").count, 1)
        self.assertEqual(tag_model.objects.get(name="product-inherited").count, 2)

    def test_failed_batch_is_atomic_and_retried_per_endpoint(self):
        self._make_endpoint("first.example.com", ["first-tag"])
        self._make_endpoint("second.example.com", ["second-tag"])

        through_model = Location.tags.through
        rows_after_batch_write = []
        rows_before_fallback = []
        call_count = 0

        def write_then_fail_once(tag_to_locations, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                bulk_add_tag_mapping(tag_to_locations, **kwargs)
                rows_after_batch_write.append(through_model.objects.count())
                msg = "simulated failure after the batch write"
                raise RuntimeError(msg)
            rows_before_fallback.append(through_model.objects.count())
            return bulk_add_tag_mapping(tag_to_locations, **kwargs)

        with (
            patch(
                "dojo.management.commands.migrate_endpoints_to_locations.bulk_add_tag_mapping",
                side_effect=write_then_fail_once,
            ),
            self.assertLogs(
                "dojo.management.commands.migrate_endpoints_to_locations",
                level="ERROR",
            ) as logs,
        ):
            call_command(
                "migrate_endpoints_to_locations",
                batch_size=2,
                progress_every=100,
                stdout=StringIO(),
            )

        # The outer transaction rolls back the completed batch before the
        # command retries its two source Endpoints independently.
        self.assertEqual(rows_after_batch_write, [2])
        self.assertEqual(rows_before_fallback[0], 0)
        self.assertEqual(through_model.objects.count(), 2)
        self.assertTrue(any("retrying one endpoint at a time" in line for line in logs.output))

        tag_model = Location.tags.tag_model
        self.assertEqual(tag_model.objects.get(name="first-tag").count, 1)
        self.assertEqual(tag_model.objects.get(name="second-tag").count, 1)

    def test_failed_endpoint_tag_retry_is_reported_and_rerunnable(self):
        failing_endpoint = self._make_endpoint("failing.example.com", ["failing-tag"])
        self._make_endpoint("healthy.example.com", ["healthy-tag"])

        def fail_one_tag(tag_to_locations, **kwargs):
            if "failing-tag" in tag_to_locations:
                msg = "simulated invalid endpoint tag"
                raise RuntimeError(msg)
            return bulk_add_tag_mapping(tag_to_locations, **kwargs)

        stdout = StringIO()
        with (
            patch(
                "dojo.management.commands.migrate_endpoints_to_locations.bulk_add_tag_mapping",
                side_effect=fail_one_tag,
            ),
            self.assertLogs(
                "dojo.management.commands.migrate_endpoints_to_locations",
                level="ERROR",
            ),
        ):
            call_command(
                "migrate_endpoints_to_locations",
                batch_size=2,
                progress_every=100,
                stdout=stdout,
            )

        self.assertIn("Migrated 1/2 endpoints", stdout.getvalue())
        self.assertIn("1 endpoint(s) failed", stdout.getvalue())
        self.assertIn(str(failing_endpoint.id), stdout.getvalue())

        failing_location = URL.objects.get(host="failing.example.com").location
        healthy_location = URL.objects.get(host="healthy.example.com").location
        self.assertEqual([tag.name for tag in failing_location.tags.all()], [])
        self.assertEqual([tag.name for tag in healthy_location.tags.all()], ["healthy-tag"])

        # A clean rerun fills only the previously failed relationship and does
        # not increment the existing healthy relationship's Tagulous count.
        rerun_stdout = StringIO()
        call_command(
            "migrate_endpoints_to_locations",
            batch_size=2,
            progress_every=100,
            stdout=rerun_stdout,
        )

        self.assertNotIn("endpoint(s) failed", rerun_stdout.getvalue())
        self.assertEqual([tag.name for tag in failing_location.tags.all()], ["failing-tag"])
        tag_model = Location.tags.tag_model
        self.assertEqual(tag_model.objects.get(name="failing-tag").count, 1)
        self.assertEqual(tag_model.objects.get(name="healthy-tag").count, 1)
