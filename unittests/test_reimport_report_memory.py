import gc
import json
import tempfile
import weakref
from unittest import mock

from django.test import override_settings
from django.utils import timezone

from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import Development_Environment, Engagement, Finding, Product, Product_Type, User

from .dojo_test_case import DojoTestCase

MATCH_BATCH = 5
BATCHES = 4


def _finding(title, line):
    return {
        "title": title,
        "description": f"{title} at line {line}",
        "severity": "High",
        "file_path": "src/app.py",
        "line": line,
        "date": "2026-07-01",
    }


# Equal, as their defaults are: a post-processing batch flushes about once per matching batch.
@override_settings(IMPORT_REIMPORT_MATCH_BATCH_SIZE=MATCH_BATCH, IMPORT_REIMPORT_DEDUPE_BATCH_SIZE=MATCH_BATCH)
class TestReimportReleasesTheReport(DojoTestCase):

    """
    How long a reimport keeps the findings it parsed from the report and the ones close-old closes.

    Regression: process_scan() kept the parsed report, and _process_findings_internal() a sorted copy of it,
    until the run ended, through close-old, the import history and the notifications; and process_scan() kept
    every finding close_old_findings() loaded and closed, though it only reads their ids afterwards. Both grew
    a large reimport's peak memory with the size of the report.
    """

    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="admin")
        product = Product.objects.create(
            name="Reimport releases the report",
            description="Test",
            prod_type=Product_Type.objects.get_or_create(name="reimport memory")[0],
        )
        self.options = {
            "user": self.user,
            "lead": self.user,
            "scan_date": None,
            "environment": Development_Environment.objects.get_or_create(name="Development")[0],
            "active": True,
            "verified": False,
            "minimum_severity": "Info",
            "scan_type": "Generic Findings Import",
        }
        self.engagement = Engagement.objects.create(
            name="Reimport memory", product=product, target_start=timezone.now(), target_end=timezone.now(),
        )

    def _scan(self, importer, findings):
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", encoding="utf-8") as scan:
            json.dump({"findings": findings}, scan)
            scan.seek(0)
            return importer.process_scan(scan)

    def test_each_batch_releases_its_report_findings_and_close_old_its_closed_ones(self):
        existing = [_finding(f"Kept {index:02d}", 10 + index) for index in range(BATCHES * MATCH_BATCH)]
        test, *_ = self._scan(DefaultImporter(engagement=self.engagement, **self.options), existing)
        kept = existing[: len(existing) // 2]
        report = kept + [_finding(f"Fresh {index:02d}", 100 + index) for index in range(len(kept))]

        parsed, closed = [], []
        alive_at_batch_start, alive_at_close_old, closed_alive_at_history = [], [], []
        original_parse = DefaultReImporter.parse_findings
        original_batch = DefaultReImporter.get_reimport_match_candidates_for_batch
        original_close_old = DefaultReImporter.close_old_findings
        original_history = DefaultReImporter.update_import_history

        def alive(refs):
            gc.collect()
            return sum(1 for ref in refs if ref() is not None)

        # Plain functions, not mocks: a mock keeps every call's arguments, and with them every batch.
        def parse_findings(importer, *args, **kwargs):
            findings = original_parse(importer, *args, **kwargs)
            parsed.extend(weakref.ref(finding) for finding in findings)
            return findings

        def batch(importer, *args, **kwargs):
            alive_at_batch_start.append(alive(parsed))
            return original_batch(importer, *args, **kwargs)

        def close_old_findings(importer, *args, **kwargs):
            alive_at_close_old.append(alive(parsed))
            result = original_close_old(importer, *args, **kwargs)
            closed.extend(weakref.ref(finding) for finding in result)
            return result

        def update_import_history(importer, *args, **kwargs):
            closed_alive_at_history.append(alive(closed))
            return original_history(importer, *args, **kwargs)

        with (
            mock.patch.object(DefaultReImporter, "parse_findings", parse_findings),
            mock.patch.object(DefaultReImporter, "get_reimport_match_candidates_for_batch", batch),
            mock.patch.object(DefaultReImporter, "close_old_findings", close_old_findings),
            mock.patch.object(DefaultReImporter, "update_import_history", update_import_history),
        ):
            _, _, len_new, len_closed, len_reactivated, len_untouched, _ = self._scan(
                DefaultReImporter(test=test, close_old_findings=True, **self.options), report,
            )

        counts = (len_new, len_closed, len_reactivated, len_untouched)
        self.assertEqual(counts, (len(kept), len(kept), 0, len(kept)), msg=f"(new, closed, reactivated, untouched)={counts}")
        self.assertEqual(len(parsed), len(report))
        self.assertEqual(len(closed), len(kept))
        # When batch k asks for its candidates, the report findings of batches k and later are still to be
        # matched. Allowed on top: one batch, the previous one's, which the loop still names until it moves on.
        still_needed = [len(report) - MATCH_BATCH * done for done in range(BATCHES)]
        self.assertEqual(len(alive_at_batch_start), BATCHES)
        over = [count - needed for count, needed in zip(alive_at_batch_start, still_needed, strict=True)]
        self.assertLessEqual(
            max(over), MATCH_BATCH,
            msg=f"parsed findings alive at the start of each batch: {alive_at_batch_start}, still needed: {still_needed}",
        )
        self.assertEqual(alive_at_close_old, [0], msg=f"parsed findings alive when close-old started: {alive_at_close_old}")
        self.assertEqual(
            closed_alive_at_history, [0],
            msg=f"closed findings alive when the import history was written: {closed_alive_at_history}",
        )
        # Control: the findings themselves are what the report says.
        self.assertEqual(Finding.objects.filter(test=test, active=True).count(), len(report))
        self.assertEqual(Finding.objects.filter(test=test, is_mitigated=True).count(), len(kept))
