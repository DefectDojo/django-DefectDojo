import logging
from unittest import mock

from django.db import IntegrityError
from django.utils import timezone

from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import (
    Development_Environment,
    Engagement,
    Product,
    Product_Type,
    Test,
    User,
)

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)

SCAN_TYPE = "Acunetix Scan"
SCAN_FILE = "one_finding.xml"


class TestImportersTagRace(DojoTestCase):

    """
    Regression: a concurrent import that shared a tag could fail the whole reimport with
    a 500.

    `update_test_tags()` writes the test's tags with `Test.tags.set(...)`. Tagulous deletes
    tag rows whose reference count drops to zero, so two imports touching the same tag can
    race: one deletes the `dojo_tagulous_test_tags` row that the other's `dojo_test_tags`
    insert references, and the M2M write fails the (deferred) foreign key check at commit
    with an IntegrityError:

        insert or update on table "dojo_test_tags" violates foreign key constraint
        "dojo_test_tags_tagulous_test_tags_i_..._fk_dojo_tagu"
        DETAIL: Key (tagulous_test_tags_id)=(...) is not present in table
        "dojo_tagulous_test_tags".

    Re-running `.set()` re-creates the vanished tag via tagulous get_or_create, so a bounded
    retry clears the race. A write that still fails after every attempt is logged and
    swallowed rather than failing an import whose findings are already saved.
    """

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="tag_race")
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        self.product, _ = Product.objects.get_or_create(
            name="TestImportersTagRace",
            description="Test",
            prod_type=product_type,
        )
        self.engagement, _ = Engagement.objects.get_or_create(
            name="Tag Race Engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        with (get_unit_tests_scans_path("acunetix") / SCAN_FILE).open(encoding="utf-8") as scan:
            self.test, _, len_new_findings, _, _, _, _ = self._importer().process_scan(scan)
        self.assertEqual(1, len_new_findings)

    def _options(self, **overrides):
        options = {
            "user": self.user,
            "lead": self.user,
            "scan_date": None,
            "environment": self.environment,
            "active": True,
            "verified": False,
            "scan_type": SCAN_TYPE,
        }
        options.update(overrides)
        return options

    def _importer(self, **overrides):
        return DefaultImporter(close_old_findings=False, **self._options(engagement=self.engagement, **overrides))

    def _reimporter(self, **overrides):
        return DefaultReImporter(close_old_findings=False, **self._options(test=self.test, **overrides))

    def test_update_test_tags_retries_past_a_transient_integrity_error(self):
        """A tag write that loses the race once is retried and the tags still land on the test."""
        reimporter = self._reimporter(tags=["alpha", "beta"])
        reimporter.test = self.test
        real_set = self.test.tags.set
        calls = {"n": 0}

        def flaky_set(tags, *args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                msg = (
                    'insert or update on table "dojo_test_tags" violates foreign key constraint '
                    '"dojo_test_tags_tagulous_test_tags_i_6336441a_fk_dojo_tagu"'
                )
                raise IntegrityError(msg)
            return real_set(tags, *args, **kwargs)

        with mock.patch.object(type(self.test.tags), "set", side_effect=flaky_set, autospec=False):
            # Must not raise: the first attempt loses the race, the second succeeds.
            reimporter.update_test_tags()

        self.assertGreaterEqual(calls["n"], 2, msg="update_test_tags must retry after an IntegrityError")
        self.assertEqual(
            {"alpha", "beta"},
            {tag.name for tag in Test.objects.get(pk=self.test.pk).tags.all()},
            msg="the tags must be persisted on the test after the retry",
        )

    def test_update_test_tags_swallows_a_persistent_integrity_error(self):
        """A tag write that keeps losing the race must not fail an import whose findings are saved."""
        reimporter = self._reimporter(tags=["alpha"])
        reimporter.test = self.test

        def always_fails(tags, *args, **kwargs):
            msg = 'Key (tagulous_test_tags_id)=(1) is not present in table "dojo_tagulous_test_tags".'
            raise IntegrityError(msg)

        with mock.patch.object(type(self.test.tags), "set", side_effect=always_fails, autospec=False):
            # Must not propagate: the reimport has already saved its findings.
            reimporter.update_test_tags()

    def test_update_test_tags_still_sets_tags_when_nothing_races(self):
        """Control case: with no race the tags are written exactly as before."""
        reimporter = self._reimporter(tags=["gamma", "delta"])
        reimporter.test = self.test

        reimporter.update_test_tags()

        self.assertEqual(
            {"gamma", "delta"},
            {tag.name for tag in Test.objects.get(pk=self.test.pk).tags.all()},
        )

    def test_update_test_tags_is_a_noop_when_no_tags_supplied(self):
        """An empty tag list must not touch existing tags (the guard the original method kept)."""
        self.test.tags.set(["preexisting"])
        reimporter = self._reimporter(tags=[])
        reimporter.test = self.test

        with mock.patch.object(type(self.test.tags), "set", side_effect=AssertionError("must not be called")):
            reimporter.update_test_tags()

        self.assertEqual(
            {"preexisting"},
            {tag.name for tag in Test.objects.get(pk=self.test.pk).tags.all()},
        )
