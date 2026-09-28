"""
Regression test: a reimport must flush its last partial batch however the loop ended.

process_findings() accumulates per-batch work (location status updates, vulnerability
ids, burp request/response pairs, parser and inherited tags, and the ids to dispatch to
post_process_findings_batch) and flushes it when the batch fills up.

The matched branch ends in `continue`. That skip is what makes the tail fragile: with the
flush living inside the loop and gated on an is_final flag, a report whose LAST finding
took the matched branch never reached it, and everything appended since the previous
size-triggered flush was dropped -- silently, because nothing raises. Those findings got
no deduplication, no rules, no issue updater, no JIRA dispatch, and none of their parser
or inherited tags.

The fix drains once after the loop instead, which runs however the last iteration ended.
"""

from unittest.mock import patch

from crum import impersonate
from django.utils import timezone

from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import (
    Development_Environment,
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
    UserContactInfo,
)

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path

SCAN_TYPE = "StackHawk HawkScan"
SCAN = get_unit_tests_scans_path("stackhawk") / "stackhawk_two_vul_same_hashcode_fabricated.json"


class TestReimportFinalDrain(DojoTestCase):

    """The last partial batch has to be flushed even when the final finding is a match."""

    def setUp(self):
        super().setUp()
        testuser, _ = User.objects.get_or_create(username="admin")
        UserContactInfo.objects.get_or_create(user=testuser, defaults={"block_execution": True})
        self.system_settings(enable_deduplication=True)
        self.system_settings(enable_product_grade=False)

        product_type, _ = Product_Type.objects.get_or_create(name="test")
        product, _ = Product.objects.get_or_create(
            name="ReimportFinalDrainTest", description="Test", prod_type=product_type,
        )
        engagement, _ = Engagement.objects.get_or_create(
            name="Test Engagement", product=product,
            target_start=timezone.now(), target_end=timezone.now(),
        )
        self.lead, _ = User.objects.get_or_create(username="admin")
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        test_type, _ = Test_Type.objects.get_or_create(name=SCAN_TYPE)
        self.test = Test.objects.create(
            engagement=engagement, test_type=test_type, scan_type=SCAN_TYPE,
            target_start=timezone.now(), target_end=timezone.now(), environment=environment,
        )

    def _reimport(self):
        with impersonate(Dojo_User.objects.get(username="admin")), SCAN.open(encoding="utf-8") as scan:
            reimporter = DefaultReImporter(
                test=self.test, user=self.lead, lead=self.lead, scan_date=None,
                minimum_severity="Info", active=True, verified=True,
                force_sync=True, scan_type=SCAN_TYPE,
            )
            return reimporter.process_scan(scan)

    def test_last_finding_taking_the_matched_branch_still_flushes_the_batch(self):
        """
        Every finding in the report must reach post-processing dispatch.

        force_continue is forced on for every match so the loop's final iteration is
        guaranteed to take the skipping branch. That is the precondition the bug needed;
        forcing it here keeps the test from depending on which finding happens to sort
        last, which is a property of the corpus rather than of the code under test.
        """
        self._reimport()
        self.assertGreater(Finding.objects.filter(test=self.test).count(), 0,
                           "the first pass must create findings, or the reimport matches nothing")

        real_process_matched = DefaultReImporter.process_matched_finding

        def always_force_continue(importer, unsaved_finding, existing_finding, *args, **kwargs):
            finding, _ = real_process_matched(importer, unsaved_finding, existing_finding, *args, **kwargs)
            return finding, True

        # bulk_apply_parser_tags is called from exactly one place, inside the flush, so it
        # stands in for "the batch was flushed" without naming the flush itself. That keeps
        # the test meaningful against the unfixed code, where no such method exists to patch.
        with (
            patch.object(DefaultReImporter, "process_matched_finding", always_force_continue),
            patch("dojo.importers.default_reimporter.bulk_apply_parser_tags") as apply_tags,
        ):
            self._reimport()

        self.assertTrue(
            apply_tags.called,
            msg=(
                "the batch was never flushed: the last finding took the matched branch's "
                "continue, so everything accumulated since the previous flush was dropped -- "
                "no deduplication, rules, issue updater or JIRA dispatch, and no parser or "
                "inherited tags for those findings"
            ),
        )
