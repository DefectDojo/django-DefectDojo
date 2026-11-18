"""
Delete Duplicates leaves excluded duplicates out of its selection before the per-run cap applies.

The task picks the excess duplicates in id order and caps them at DUPE_DELETE_MAX_PER_RUN. A
duplicate that is only set aside after that (by the deletion step, or a plugin wrapping it) still
took a place under the cap, so the duplicates of one asset that must not lose any could hold the
head of the selection and stop Delete Duplicates for every other asset, every run.
"""

from unittest.mock import patch

from django.db.models import Q
from django.test.utils import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from dojo import tasks as dojo_tasks
from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_Member,
    Product_Type,
    Role,
    System_Settings,
    Test,
    Test_Type,
    User,
)
from dojo.tasks import _async_dupe_delete_impl  # noqa: PLC2701

from .dojo_test_case import DojoTestCase


# Regression: one asset's duplicates set aside after the capped selection stop Delete Duplicates for every asset
@override_settings(DUPE_DELETE_GRACE_MINUTES=0, DUPE_DELETE_MAX_PER_RUN=2)
class TestDupeDeleteSelectionExclude(DojoTestCase):

    def setUp(self):
        # Start from empty registries: whatever a plugin installed in this process registered is not under test.
        for registry in ("_dupe_delete_excludes", "_dupe_delete_limits", "_dupe_delete_done"):
            patcher = patch.object(dojo_tasks, registry, [])
            patcher.start()
            self.addCleanup(patcher.stop)
        system_settings, _ = System_Settings.objects.get_or_create(id=1)
        system_settings.delete_duplicates = True
        system_settings.max_dupes = 1
        system_settings.enable_product_grade = False
        system_settings.save()
        self.reporter = User.objects.create(username="dupe-delete-exclude-reporter")
        self.test_type, _ = Test_Type.objects.get_or_create(name="Dupe Delete Exclude Scan")
        product_type = Product_Type.objects.create(name="Dupe Delete Exclude")
        self.held_product = Product.objects.create(name="Held Asset", description="held", prod_type=product_type)
        self.other_product = Product.objects.create(name="Other Asset", description="other", prod_type=product_type)
        # Created first, so the held asset's excess duplicates have the lowest ids and fill the cap.
        self.held_excess = self._cluster(self.held_product, "held", duplicates=4)
        self.other_excess = self._cluster(self.other_product, "other", duplicates=3)
        self.assertLess(max(self.held_excess), min(self.other_excess))

    def _cluster(self, product, label, duplicates):
        """An original and `duplicates` older duplicates of it; returns the ids max_dupes=1 makes excess."""
        now = timezone.now()
        engagement = Engagement.objects.create(name=label, product=product, target_start=now, target_end=now)
        test = Test.objects.create(engagement=engagement, test_type=self.test_type, target_start=now, target_end=now)
        original = self._finding(test, f"{label} original", "2025-01-01", duplicate_of=None)
        ids = [
            self._finding(test, f"{label} dupe {n}", f"2024-01-{n + 1:02d}", duplicate_of=original).id
            for n in range(duplicates)
        ]
        # Kept: the newest duplicate. Excess: the rest.
        return sorted(ids[:-1])

    def _finding(self, test, title, date, duplicate_of):
        finding = Finding(
            test=test,
            title=title,
            date=date,
            severity="High",
            numerical_severity="S1",
            reporter=self.reporter,
            duplicate=duplicate_of is not None,
            duplicate_finding=duplicate_of,
        )
        finding.save(dedupe_option=False, rules_option=False, product_grading_option=False)
        return finding

    def _register(self, exclude):
        dojo_tasks.register_dupe_delete_exclude(exclude)
        self.addCleanup(dojo_tasks._dupe_delete_excludes.clear)

    def _remaining(self, ids):
        return set(Finding.objects.filter(id__in=ids).values_list("id", flat=True))

    def test_nothing_registered_selection_is_unchanged(self):
        _async_dupe_delete_impl()

        self.assertEqual(
            self._remaining(self.held_excess),
            set(self.held_excess[2:]),
            "With no exclude registered the two lowest-id excess duplicates are the ones deleted",
        )
        self.assertEqual(self._remaining(self.other_excess), set(self.other_excess))

    def test_excluded_asset_does_not_use_the_cap(self):
        held_id = self.held_product.id
        self._register(lambda: Q(test__engagement__product_id=held_id))

        _async_dupe_delete_impl()

        remaining_held = self._remaining(self.held_excess)
        remaining_other = self._remaining(self.other_excess)
        self.assertEqual(remaining_held, set(self.held_excess), f"held asset lost duplicates: left {remaining_held}")
        self.assertEqual(
            remaining_other,
            set(),
            f"the other asset's excess duplicates should be deleted in the same run, left {remaining_other}",
        )

    def test_an_exclude_returning_none_excludes_nothing(self):
        self._register(lambda: None)

        _async_dupe_delete_impl()

        self.assertEqual(self._remaining(self.held_excess), set(self.held_excess[2:]))

    def test_registering_the_same_exclude_twice_keeps_one(self):
        def exclude():
            return None

        self._register(exclude)
        self._register(exclude)

        self.assertEqual(dojo_tasks._dupe_delete_excludes, [exclude])

    def test_a_limit_decides_which_selected_duplicates_are_deleted(self):
        seen = []

        def keep_the_first(ids):
            seen.append(list(ids))
            return ids[:1]

        dojo_tasks.register_dupe_delete_limit(keep_the_first)
        self.addCleanup(dojo_tasks._dupe_delete_limits.clear)

        _async_dupe_delete_impl()

        self.assertEqual(seen, [self.held_excess[:2]], f"the limit should see the capped selection once, saw {seen}")
        self.assertEqual(
            self._remaining(self.held_excess),
            set(self.held_excess[1:]),
            "only the id the limit returned should be deleted",
        )

    def test_a_limit_is_not_called_when_nothing_is_selected(self):
        calls = []
        dojo_tasks.register_dupe_delete_limit(lambda ids: calls.append(ids) or ids)
        self.addCleanup(dojo_tasks._dupe_delete_limits.clear)
        Product.objects.update(dupe_delete_held_at=timezone.now())

        _async_dupe_delete_impl()

        self.assertEqual(calls, [])

    def test_a_done_callback_gets_exactly_the_deleted_ids(self):
        calls = []
        dojo_tasks.register_dupe_delete_done(lambda ids: calls.append(sorted(ids)))
        dojo_tasks.register_dupe_delete_done(calls.append)
        # The second test's duplicates are under import: selected, but left for a later run.
        busy = Finding.objects.get(id=self.held_excess[1]).test_id
        with patch.object(dojo_tasks, "tests_under_import_now", lambda tests: {busy} & set(tests)):
            _async_dupe_delete_impl()

        self.assertEqual(calls[0], [], f"only deleted ids are reported, got {calls}")
        self.assertEqual(len(calls), 2, "every registered callback is called")

    def test_a_done_callback_is_not_called_when_nothing_is_selected(self):
        calls = []
        dojo_tasks.register_dupe_delete_done(calls.append)
        Product.objects.update(dupe_delete_held_at=timezone.now())

        _async_dupe_delete_impl()

        self.assertEqual(calls, [])

    def test_a_done_callback_gets_the_deleted_ids(self):
        calls = []
        dojo_tasks.register_dupe_delete_done(lambda ids: calls.append(sorted(ids)))

        _async_dupe_delete_impl()

        self.assertEqual(calls, [self.held_excess[:2]])

    def test_a_held_asset_is_left_out_with_nothing_registered(self):
        Product.objects.filter(id=self.held_product.id).update(dupe_delete_held_at=timezone.now())

        _async_dupe_delete_impl()

        remaining_held = self._remaining(self.held_excess)
        remaining_other = self._remaining(self.other_excess)
        self.assertEqual(remaining_held, set(self.held_excess), f"held asset lost duplicates: left {remaining_held}")
        self.assertEqual(remaining_other, set(), f"other asset should be cleaned, left {remaining_other}")

    def test_clearing_the_hold_resumes_deletion(self):
        Product.objects.filter(id=self.held_product.id).update(dupe_delete_held_at=timezone.now())
        _async_dupe_delete_impl()
        Product.objects.filter(id=self.held_product.id).update(dupe_delete_held_at=None)

        _async_dupe_delete_impl()

        self.assertEqual(self._remaining(self.held_excess), set(self.held_excess[2:]))


@override_settings(SECURE_SSL_REDIRECT=False)
class TestClearDupeDeleteHoldApi(DojoTestCase):

    """POST /api/v2/products/{id}/clear_dupe_delete_hold/ lifts a hold; only a superuser may."""

    def setUp(self):
        System_Settings.objects.get_or_create(id=1)
        product_type = Product_Type.objects.create(name="Dupe Delete Hold API")
        self.product = Product.objects.create(name="Held Asset API", description="held", prod_type=product_type)
        Product.objects.filter(pk=self.product.pk).update(dupe_delete_held_at=timezone.now())
        self.url = reverse("product-clear-dupe-delete-hold", args=[self.product.pk])
        self.superuser = User.objects.create(username="hold-superuser", is_superuser=True, is_staff=True)
        self.owner = User.objects.create(username="hold-owner")
        Product_Member.objects.create(product=self.product, user=self.owner, role=Role.objects.get(name="Owner"))

    def _client(self, user):
        client = APIClient()
        client.force_authenticate(user=user)
        return client

    def _held_at(self):
        return Product.objects.get(pk=self.product.pk).dupe_delete_held_at

    def test_a_superuser_clears_the_hold(self):
        response = self._client(self.superuser).post(self.url)

        self.assertEqual(response.status_code, 204, response.content[:500])
        self.assertIsNone(self._held_at(), f"hold still set: {self._held_at()}")

    def test_clearing_an_asset_that_is_not_held_succeeds(self):
        Product.objects.filter(pk=self.product.pk).update(dupe_delete_held_at=None)

        response = self._client(self.superuser).post(self.url)

        self.assertEqual(response.status_code, 204, response.content[:500])
        self.assertIsNone(self._held_at())

    def test_an_asset_owner_cannot_clear_the_hold(self):
        response = self._client(self.owner).post(self.url)

        self.assertEqual(response.status_code, 403, response.content[:500])
        self.assertIsNotNone(self._held_at(), "an owner's request lifted the hold")

    def test_an_anonymous_request_cannot_clear_the_hold(self):
        response = APIClient().post(self.url)

        self.assertIn(response.status_code, {401, 403}, response.content[:500])
        self.assertIsNotNone(self._held_at())

    def test_the_hold_is_read_only_through_the_product_endpoint(self):
        detail = reverse("product-detail", args=[self.product.pk])
        client = self._client(self.superuser)

        read = client.get(detail)
        response = client.patch(detail, {"dupe_delete_held_at": None}, format="json")

        self.assertEqual(read.status_code, 200, read.content[:500])
        self.assertIsNotNone(read.data["dupe_delete_held_at"], "the hold should be visible on the product")
        self.assertEqual(response.status_code, 200, response.content[:500])
        self.assertIsNotNone(self._held_at(), "PATCH must not lift the hold; only the clear action may")

    def test_held_assets_can_be_listed_on_both_routes(self):
        unheld = Product.objects.create(name="Unheld Asset API", description="unheld", prod_type=self.product.prod_type)
        client = self._client(self.superuser)

        for route in ("product-list", "asset-list"):
            held = client.get(reverse(route), {"dupe_delete_held": "true"})
            not_held = client.get(reverse(route), {"dupe_delete_held": "false"})

            self.assertEqual(held.status_code, 200, held.content[:300])
            held_ids = {row["id"] for row in held.data["results"]}
            not_held_ids = {row["id"] for row in not_held.data["results"]}
            self.assertIn(self.product.pk, held_ids, route)
            self.assertNotIn(unheld.pk, held_ids, route)
            self.assertIn(unheld.pk, not_held_ids, route)
            self.assertNotIn(self.product.pk, not_held_ids, route)

    def test_the_asset_endpoint_clears_the_hold_too(self):
        url = reverse("asset-clear-dupe-delete-hold", args=[self.product.pk])

        refused = self._client(self.owner).post(url)
        cleared = self._client(self.superuser).post(url)

        self.assertEqual(refused.status_code, 403, refused.content[:500])
        self.assertEqual(cleared.status_code, 204, cleared.content[:500])
        self.assertIsNone(self._held_at())
