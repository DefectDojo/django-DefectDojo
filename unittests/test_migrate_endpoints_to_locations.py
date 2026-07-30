import datetime
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from dojo.location.models import (
    Location,
    LocationFindingReference,
    LocationProductReference,
)
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.models import (
    Dojo_User,
    DojoMeta,
    Endpoint,
    Endpoint_Status,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)
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
        self.reporter = Dojo_User.objects.create(username="endpoint-migration-reporter")

    def _make_endpoint(self, host, tags):
        with Endpoint.allow_endpoint_init():
            endpoint = Endpoint.objects.create(
                protocol="https",
                host=host,
                product=self.product,
            )
        endpoint.tags.add(*tags)
        return endpoint

    def _make_test(self):
        engagement = Engagement.objects.create(
            name="Endpoint migration engagement",
            product=self.product,
            target_start=timezone.now().date(),
            target_end=timezone.now().date(),
        )
        test_type, _ = Test_Type.objects.get_or_create(name="Endpoint migration test type")
        return Test.objects.create(
            engagement=engagement,
            test_type=test_type,
            scan_type="Endpoint migration scan",
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _make_endpoint_with_status(self, host, *, active, test=None, title=None):
        """Create an Endpoint carrying one Endpoint_Status for a new Finding."""
        test = test or self._make_test()
        finding = Finding.objects.create(
            title=title or f"Finding for {host}",
            test=test,
            severity="High",
            numerical_severity="S1",
            description="Test finding",
            active=active,
            verified=False,
            reporter=self.reporter,
        )
        with Endpoint.allow_endpoint_init():
            endpoint = Endpoint.objects.create(
                protocol="https",
                host=host,
                product=self.product,
            )
        status = Endpoint_Status.objects.create(
            endpoint=endpoint,
            finding=finding,
            date=datetime.date(2024, 5, 17),
            mitigated=not active,
        )
        return endpoint, finding, status

    def _run(self, **kwargs):
        stdout = StringIO()
        call_command(
            "migrate_endpoints_to_locations",
            progress_every=kwargs.pop("progress_every", 100),
            stdout=stdout,
            **kwargs,
        )
        return stdout.getvalue()

    def _location_for(self, host):
        return URL.objects.get(host=host).location

    def test_endpoint_tags_are_copied_in_deduplicated_batches(self):
        # Four legacy Endpoints resolve to one Location. With batches of three,
        # at least one batch contains that Location more than once regardless of
        # database row order, so this exercises in-batch deduplication without
        # relying on an implicit queryset order.
        # Seed the Product tag before enabling propagation so setup does not
        # dispatch an unrelated asynchronous inheritance task.
        self.product.tags.add("product-inherited")
        self.product.enable_product_tag_inheritance = True
        self.product.save(update_fields=["enable_product_tag_inheritance"])
        self._make_endpoint("shared.example.com", ["shared", "secondary"])
        self._make_endpoint("shared.example.com", ["shared"])
        self._make_endpoint("shared.example.com", ["shared"])
        self._make_endpoint("shared.example.com", ["shared"])
        self._make_endpoint("unique.example.com", ["shared"])

        with patch(
            "dojo.management.commands.migrate_endpoints_to_locations.bulk_add_tag_mapping",
            wraps=bulk_add_tag_mapping,
        ) as bulk_add:
            call_command(
                "migrate_endpoints_to_locations",
                batch_size=3,
                progress_every=100,
                stdout=StringIO(),
            )

        self.assertEqual(bulk_add.call_count, 2)
        shared_locations_written = sum(
            len(call.args[0]["shared"]) for call in bulk_add.call_args_list
        )
        self.assertEqual(shared_locations_written, 3)

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
            batch_size=3,
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

    def test_rerun_creates_no_duplicate_rows(self):
        self._make_endpoint_with_status("idempotent.example.com", active=True)
        endpoint = self._make_endpoint("plain.example.com", ["plain-tag"])
        DojoMeta.objects.create(name="owner", value="team-a", endpoint=endpoint)

        self._run()
        location = self._location_for("idempotent.example.com")
        first_created = LocationFindingReference.objects.get(location=location).created
        counts = (
            Location.objects.count(),
            URL.objects.count(),
            LocationFindingReference.objects.count(),
            LocationProductReference.objects.count(),
            DojoMeta.objects.filter(location__isnull=False).count(),
        )
        self.assertEqual(counts, (2, 2, 1, 2, 1))

        self._run()

        self.assertEqual(
            (
                Location.objects.count(),
                URL.objects.count(),
                LocationFindingReference.objects.count(),
                LocationProductReference.objects.count(),
                DojoMeta.objects.filter(location__isnull=False).count(),
            ),
            counts,
        )
        # A rerun must not restamp `created` on a reference it already wrote.
        self.assertEqual(
            LocationFindingReference.objects.get(location=location).created,
            first_created,
        )

    def test_rerun_syncs_changed_finding_reference_status(self):
        _, _, status = self._make_endpoint_with_status("changed.example.com", active=True)
        self._run()

        location = self._location_for("changed.example.com")
        reference = LocationFindingReference.objects.get(location=location)
        self.assertEqual(reference.status, FindingLocationStatus.Active)
        created_before = reference.created

        # The source Endpoint_Status moves on after the first migration.
        Endpoint_Status.objects.filter(pk=status.pk).update(risk_accepted=True)

        self._run()

        reference.refresh_from_db()
        self.assertEqual(reference.status, FindingLocationStatus.RiskAccepted)
        self.assertEqual(reference.created, created_before)
        self.assertEqual(LocationFindingReference.objects.count(), 1)

    def test_product_reference_status_is_reconciled_from_finding_references(self):
        # Two endpoints sharing one product; only the first has an active
        # finding, so the product reference for its location must be Active and
        # the other's Mitigated.
        test = self._make_test()
        _, _, active_status = self._make_endpoint_with_status(
            "active.example.com", active=True, test=test, title="Active finding",
        )
        self._make_endpoint_with_status(
            "mitigated.example.com", active=False, test=test, title="Mitigated finding",
        )

        self._run()

        active_location = self._location_for("active.example.com")
        mitigated_location = self._location_for("mitigated.example.com")
        self.assertEqual(
            LocationProductReference.objects.get(
                location=active_location, product=self.product,
            ).status,
            ProductLocationStatus.Active,
        )
        self.assertEqual(
            LocationProductReference.objects.get(
                location=mitigated_location, product=self.product,
            ).status,
            ProductLocationStatus.Mitigated,
        )

        # A status that drifted out of sync with the finding references is
        # repaired rather than left alone by `ignore_conflicts`.
        LocationProductReference.objects.filter(location=active_location).update(
            status=ProductLocationStatus.Mitigated,
        )
        self._run()
        self.assertEqual(
            LocationProductReference.objects.get(
                location=active_location, product=self.product,
            ).status,
            ProductLocationStatus.Active,
        )

        # And a genuine downgrade in the source data propagates: the previous
        # per-endpoint code left the first-written Active status in place.
        Endpoint_Status.objects.filter(pk=active_status.pk).update(mitigated=True)
        self._run()
        self.assertEqual(
            LocationProductReference.objects.get(
                location=active_location, product=self.product,
            ).status,
            ProductLocationStatus.Mitigated,
        )

    def test_shared_location_product_status_is_order_independent(self):
        # Two endpoints normalising onto the same Location, split across
        # separate chunks, with only the second carrying the active finding.
        test = self._make_test()
        for title, active in (("Mitigated first", False), ("Active second", True)):
            finding = Finding.objects.create(
                title=title,
                test=test,
                severity="High",
                numerical_severity="S1",
                description="Test finding",
                active=active,
                verified=False,
                reporter=self.reporter,
            )
            with Endpoint.allow_endpoint_init():
                endpoint = Endpoint.objects.create(
                    protocol="https", host="shared-status.example.com", product=self.product,
                )
            Endpoint_Status.objects.create(
                endpoint=endpoint,
                finding=finding,
                date=datetime.date(2024, 5, 17),
                mitigated=not active,
            )

        self._run(batch_size=1)

        location = self._location_for("shared-status.example.com")
        self.assertEqual(URL.objects.filter(host="shared-status.example.com").count(), 1)
        self.assertEqual(LocationFindingReference.objects.filter(location=location).count(), 2)
        self.assertEqual(
            LocationProductReference.objects.get(
                location=location, product=self.product,
            ).status,
            ProductLocationStatus.Active,
        )

    def test_invalid_endpoint_is_reported_and_its_chunk_still_migrates(self):
        # `bulk_get_or_create` only calls clean(), so the command validates each
        # URL itself to keep an endpoint that cannot pass field validation from
        # being written as an invalid Location.
        self._make_endpoint("good-one.example.com", [])
        self._make_endpoint("good-two.example.com", [])
        broken = self._make_endpoint("broken.example.com", [])
        Endpoint.objects.filter(pk=broken.pk).update(host="")

        stdout = StringIO()
        with self.assertLogs(
            "dojo.management.commands.migrate_endpoints_to_locations",
            level="ERROR",
        ) as logs:
            call_command(
                "migrate_endpoints_to_locations",
                batch_size=10,
                progress_every=100,
                stdout=stdout,
            )

        self.assertIn("Migrated 2/3 endpoints", stdout.getvalue())
        self.assertIn(str(broken.id), stdout.getvalue())
        self.assertTrue(
            any(f"Failed to migrate endpoint id={broken.id}" in line for line in logs.output),
        )
        self.assertEqual(
            sorted(URL.objects.values_list("host", flat=True)),
            ["good-one.example.com", "good-two.example.com"],
        )

    def test_failed_bulk_location_write_falls_back_per_endpoint(self):
        self._make_endpoint("first-bulk.example.com", [])
        self._make_endpoint("second-bulk.example.com", [])

        original = URL.bulk_get_or_create
        calls = []

        def fail_first_chunk(locations):
            calls.append(len(locations))
            if len(calls) == 1:
                msg = "simulated bulk location write failure"
                raise RuntimeError(msg)
            return original(locations)

        stdout = StringIO()
        with (
            patch.object(URL, "bulk_get_or_create", side_effect=fail_first_chunk),
            self.assertLogs(
                "dojo.management.commands.migrate_endpoints_to_locations",
                level="ERROR",
            ) as logs,
        ):
            call_command(
                "migrate_endpoints_to_locations",
                batch_size=10,
                progress_every=100,
                stdout=stdout,
            )

        self.assertTrue(
            any("falling back to one get_or_create per endpoint" in line for line in logs.output),
        )
        # Every endpoint still migrates, via the per-endpoint path.
        self.assertIn("Migrated 2/2 endpoints", stdout.getvalue())
        self.assertEqual(
            sorted(URL.objects.values_list("host", flat=True)),
            ["first-bulk.example.com", "second-bulk.example.com"],
        )

    def test_inheritance_signal_is_suppressed_during_the_main_loop(self):
        # The per-Location post_save inheritance signal issues an OR-joined
        # query whose cost grows with LocationFindingReference, so the hot loop
        # must not fire it; `_run_tag_inheritance` applies inheritance in bulk
        # once the reference rows exist.
        self.product.tags.add("product-inherited")
        self.product.enable_product_tag_inheritance = True
        self.product.save(update_fields=["enable_product_tag_inheritance"])
        self._make_endpoint_with_status("inherit.example.com", active=True)

        with patch(
            "dojo.location.models.Location.all_related_products",
        ) as all_related_products:
            self._run()

        all_related_products.assert_not_called()

        location = self._location_for("inherit.example.com")
        self.assertEqual(
            [tag.name for tag in location.inherited_tags.all()],
            ["product-inherited"],
        )
