"""
The extension points ``manage.py dedupe`` offers, and that its own run goes through them.

Editions that store extra hash fields or need extra scoping subclass this command instead of
forking it. The fork is what let the two copies drift -- the location prefetch and the
vulnerability-id prefetch each had to be fixed twice because of one -- so this pins the contract a
subclass relies on: every hook has a working default, and the run actually calls it.

No fixtures beyond one product tree, and the recompute is stubbed, so nothing here depends on
deduplication actually running.
"""
import logging
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.utils import timezone

from dojo.management.commands.dedupe import Command, generate_hash_code
from dojo.models import Engagement, Finding, Product, Product_Type, Test, Test_Type

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)

User = get_user_model()

DEFAULT_OPTIONS = {
    "parser": None,
    "hash_code_only": True,
    "dedupe_only": False,
    "dedupe_sync": False,
    "dedupe_batch_mode": True,
}


class TestDedupeCommandHookDefaults(DojoTestCase):

    """Every hook has a default, so the base command is usable without a subclass."""

    def setUp(self):
        super().setUp()
        self.command = Command()

    def test_extra_scope_defaults_to_no_narrowing(self):
        queryset = Finding.objects.all()
        self.assertIs(self.command.apply_extra_scope(queryset, {}), queryset)

    def test_extra_scope_description_defaults_to_nothing(self):
        self.assertEqual(self.command.describe_extra_scope({}), [])

    def test_the_default_hash_generator_is_the_module_level_one(self):
        self.assertIs(self.command.hash_code_generator(), generate_hash_code)

    def test_there_are_no_extra_hashes_by_default(self):
        """The base edition stores only Finding.hash_code, so this is a no-op."""
        self.assertIsNone(self.command.recompute_extra_hashes(Finding.objects.none(), None))

    def test_adding_extra_arguments_defaults_to_nothing(self):
        """A subclass that adds no arguments must not have to define the hook."""
        with patch("argparse.ArgumentParser.add_argument") as mock_add:
            self.assertIsNone(self.command.add_extra_arguments(None))
        mock_add.assert_not_called()


@override_settings(V3_FEATURE_LOCATIONS=True)
class TestDedupeCommandCallsItsHooks(DojoTestCase):

    """A subclass's hooks have to actually be reached by the run."""

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        product_type = Product_Type.objects.create(name="Org for dedupe hooks")
        self.product = Product.objects.create(
            name="Product for dedupe hooks",
            description="hook fixture",
            prod_type=product_type,
        )
        engagement = Engagement.objects.create(
            name="Engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.test = Test.objects.create(
            engagement=engagement,
            test_type=Test_Type.objects.get_or_create(name="Manual Test")[0],
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        Finding.objects.create(
            test=self.test,
            title="Finding for dedupe hooks",
            severity="High",
            description="hook fixture",
            mitigation="n/a",
            impact="n/a",
            reporter=self.user,
        )

    def _subclass(self):
        """A subclass recording what the run asked of it."""
        calls = []

        class Subclassed(Command):
            def apply_extra_scope(self, findings, options):
                calls.append(("apply_extra_scope", options.get("marker")))
                return findings.filter(title__startswith="Finding")

            def describe_extra_scope(self, options):
                calls.append(("describe_extra_scope", None))
                return ["marker=on"]

            def hash_code_generator(self):
                calls.append(("hash_code_generator", None))
                return generate_hash_code

            def recompute_extra_hashes(self, findings, writer):
                calls.append(("recompute_extra_hashes", None))

        return Subclassed(), calls

    def test_the_hash_phase_goes_through_the_hooks(self):
        command, calls = self._subclass()

        command.handle(**DEFAULT_OPTIONS, marker="on")

        called = [name for name, _ in calls]
        self.assertIn("apply_extra_scope", called)
        self.assertIn("describe_extra_scope", called)
        self.assertIn("hash_code_generator", called)
        self.assertIn(
            "recompute_extra_hashes", called,
            msg="an edition with extra hash fields must get its second pass",
        )

    def test_extra_scope_receives_the_parsed_options(self):
        """A subclass reads its own arguments out of options, so they have to be passed through."""
        command, calls = self._subclass()

        command.handle(**DEFAULT_OPTIONS, marker="on")

        self.assertIn(("apply_extra_scope", "on"), calls)

    def test_dedupe_only_skips_the_extra_hash_pass(self):
        """--dedupe_only means recompute nothing, including the edition's extra hashes."""
        command, calls = self._subclass()

        with patch.object(Command, "_dedupe_batch_mode"):
            command.handle(**{**DEFAULT_OPTIONS, "hash_code_only": False, "dedupe_only": True}, marker="on")

        self.assertNotIn("recompute_extra_hashes", [name for name, _ in calls])

    def test_the_batch_dedupe_hooks_are_used(self):
        """Both batch paths route through the overridable hooks rather than calling directly."""
        command, _ = self._subclass()

        with (
            patch.object(Command, "dedupe_batch_async") as mock_async,
            patch("dojo.management.commands.dedupe.get_system_setting", return_value=True),
        ):
            command.handle(**{**DEFAULT_OPTIONS, "hash_code_only": False}, marker="on")

        mock_async.assert_called()

    def test_grading_goes_through_its_hook_in_sync_mode(self):
        command, _ = self._subclass()

        with (
            patch.object(Command, "grade_product") as mock_grade,
            patch.object(Command, "_dedupe_batch_mode"),
            patch("dojo.management.commands.dedupe.get_system_setting", return_value=True),
        ):
            command.handle(**{**DEFAULT_OPTIONS, "hash_code_only": False, "dedupe_sync": True}, marker="on")

        mock_grade.assert_called()
