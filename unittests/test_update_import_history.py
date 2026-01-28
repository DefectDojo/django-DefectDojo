import logging
from unittest.mock import patch

from django.contrib.auth.models import User as DjangoUser
from django.test import TransactionTestCase, tag
from django.utils import timezone

from dojo.importers.default_importer import DefaultImporter
from dojo.models import (
    Development_Environment,
    Engagement,
    Finding,
    Product,
    Product_Type,
    SLA_Configuration,
    Test,
    Test_Import_Finding_Action,
)

logger = logging.getLogger(__name__)


# we need to run this as a TransactionTestCase to be able to mimic the behavior of the bulk_create fallback at runtime when a FK violation occurs


@tag("transactional")
class UpdateImportHistoryTests(TransactionTestCase):

    # loading fixtures fails in TransactionTestCase, not sure why. possibly because they are not up-to-date and missing fields like sla_configuration
    # creating testdata via code is a better approach, at least here.
    def setUp(self):
        super().setUp()
        self.env, _ = Development_Environment.objects.get_or_create(name="Development")
        self.prod_type = Product_Type.objects.create(name="UpdateImportHistory PT")
        # Ensure a valid SLA configuration exists and is assigned explicitly to avoid default FK issues
        self.sla = SLA_Configuration.objects.create(name="UpdateImportHistory SLA")
        self.prod = Product.objects.create(
            name="UpdateImportHistory P",
            description="test",
            prod_type=self.prod_type,
            sla_configuration=self.sla,
        )
        self.eng = Engagement.objects.create(
            name="UpdateImportHistory E",
            product=self.prod,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        # Ensure a reporter/lead user exists for FK constraints
        self.user = DjangoUser.objects.create(username="admin")

        # Minimal importer
        self.importer = DefaultImporter(
            user=self.user,
            lead=self.user,
            environment=self.env,
            engagement=self.eng,
            minimum_severity="Info",
            active=True,
            verified=True,
            sync=True,
            scan_type="StackHawk HawkScan",
        )
        # Explicitly create the Test similar to Engagement creation
        self.test = Test.objects.create(
            title="UpdateImportHistory T",
            engagement=self.eng,
            lead=self.user,
            environment=self.env,
            test_type=self.importer.get_or_create_test_type("StackHawk HawkScan"),
            scan_type="StackHawk HawkScan",
            target_start=timezone.now(),
            target_end=timezone.now(),
            percent_complete=0,
        )
        # Attach to importer
        self.importer.test = self.test

    def _create_findings(self, count):
        findings = []
        for i in range(count):
            f = Finding(
                title=f"F{i}",
                test=self.importer.test,
                severity="Low",
                reporter=self.user,
            )
            f.save()
            findings.append(f)
        return findings

    def test_success_path_creates_expected_actions(self):
        new_findings = self._create_findings(5)
        closed_findings = self._create_findings(3)

        test_import = self.importer.update_import_history(
            new_findings=new_findings,
            closed_findings=closed_findings,
        )

        total_expected = len(new_findings) + len(closed_findings)
        created = Test_Import_Finding_Action.objects.filter(test_import=test_import).count()
        self.assertEqual(created, total_expected)

    def test_fk_violation_in_batch_results_in_partial_fallback(self):
        # One bad finding (deleted after pre-check) triggers IntegrityError; fallback saves the valid ones
        new_findings = self._create_findings(9)
        bad = self._create_findings(1)[0]

        # Patch the existence filter to return all findings as-if they exist, then delete to simulate race after check
        with patch("dojo.finding.helper.filter_findings_by_existence", side_effect=lambda lst: lst):
            bad_id = bad.id
            Finding.objects.filter(id=bad_id).delete()
            test_import = self.importer.update_import_history(new_findings=[*new_findings, bad])

        created = Test_Import_Finding_Action.objects.filter(test_import=test_import).count()
        # Expect only the 9 valid ones to be created; the bad one is skipped/raises during fallback
        self.assertEqual(created, len(new_findings))

    def test_fk_violation_second_batch_results_in_partial_fallback(self):
        # Create 300 findings so Django's bulk_create will batch internally (batch_size=100)
        total = 300
        new_findings = self._create_findings(total)

        # Delete a finding in the second batch (index 150) after the existence check
        bad = new_findings[150]
        with patch("dojo.finding.helper.filter_findings_by_existence", side_effect=lambda lst: lst):
            Finding.objects.filter(id=bad.id).delete()
            test_import = self.importer.update_import_history(new_findings=new_findings)

        # Expect all but the deleted one to be created via fallback
        created = Test_Import_Finding_Action.objects.filter(test_import=test_import).count()
        self.assertEqual(created, total - 1)

    def test_precheck_filters_out_deleted_findings_allows_successful_bulk(self):
        # If a finding is deleted before the existence check, it should be filtered out
        new_findings = self._create_findings(5)
        closed_findings = self._create_findings(3)

        # Delete one from new and one from closed before calling update_import_history
        Finding.objects.filter(id=new_findings[0].id).delete()
        Finding.objects.filter(id=closed_findings[0].id).delete()

        test_import = self.importer.update_import_history(
            new_findings=new_findings,
            closed_findings=closed_findings,
        )

        expected = (len(new_findings) - 1) + (len(closed_findings) - 1)
        created = Test_Import_Finding_Action.objects.filter(test_import=test_import).count()
        self.assertEqual(created, expected)
