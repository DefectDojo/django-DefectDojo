from unittest.mock import patch

from django.utils.timezone import now

from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import (
    Development_Environment,
    Dojo_User,
    Engagement,
    Finding,
    Finding_Group,
    Product,
    Product_Type,
    Test,
    Test_Type,
)

from .dojo_test_case import DojoTestCase


class TestReimportGroupJiraSync(DojoTestCase):

    """
    process_groups_for_all_findings() re-derives which finding groups to push to JIRA from
    the reactivated/unchanged buckets. Since those buckets became plain ids, the group
    membership is resolved with a query instead of off in-memory instances.

    Finding has no finding_group_id column -- Finding.finding_group is a cached_property over
    the reverse M2M finding_group_set -- so selecting "finding_group_id" raises FieldError and
    500s the whole reimport, but only when finding groups are enabled AND JIRA push/sync is on,
    which no other test exercises. This pins that the query runs and resolves the right group.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(username="reimport-group-jira-user")
        cls.prod_type = Product_Type.objects.create(name="Reimport Group JIRA Type")
        cls.product = Product.objects.create(
            name="Reimport Group JIRA Product", prod_type=cls.prod_type, description="x",
        )
        cls.engagement = Engagement.objects.create(
            name="Reimport Group JIRA Engagement",
            product=cls.product,
            target_start=now(),
            target_end=now(),
        )
        cls.test_type = Test_Type.objects.create(name="Reimport Group JIRA Test Type")
        cls.environment = Development_Environment.objects.create(name="Reimport Group JIRA Env")
        cls.test = Test.objects.create(
            engagement=cls.engagement,
            test_type=cls.test_type,
            environment=cls.environment,
            target_start=now(),
            target_end=now(),
        )
        cls.finding = Finding.objects.create(
            title="grouped active finding", test=cls.test, severity="High", reporter=cls.user,
        )
        cls.group = Finding_Group.objects.create(
            name="reimport group", test=cls.test, creator=cls.user,
        )
        cls.group.findings.set([cls.finding])

    def _reimporter(self):
        importer = DefaultReImporter(
            close_old_findings=False,
            test=self.test,
            user=self.user,
            lead=self.user,
            scan_date=None,
            environment=self.environment,
            active=True,
            verified=False,
            scan_type=self.test_type.name,
        )
        # The buckets this method reads are ids after the by-id refactor. An unchanged, still
        # active finding that belongs to a group is the shape that hits the group query.
        importer.reactivated_items = []
        importer.unchanged_items = [self.finding.id]
        importer.group_names_to_findings_dict = {}  # skip the per-group loop; isolate the query
        importer.findings_groups_enabled = True
        importer.push_to_jira = True
        importer.jira_instance = None
        return importer

    def test_group_jira_sync_query_resolves_the_group_without_a_fielderror(self):
        importer = self._reimporter()

        with patch("dojo.importers.default_reimporter.jira_services.push") as mock_push:
            # Before the fix this raised FieldError: Cannot resolve keyword 'finding_group_id'.
            importer.process_groups_for_all_findings()

        mock_push.assert_called_once()
        pushed = mock_push.call_args.args[0]
        self.assertEqual(pushed.id, self.group.id)

    def test_no_group_push_when_no_unchanged_or_reactivated_finding_is_grouped(self):
        """
        A guard so the assertion above proves the query, not a blanket push: with empty
        buckets the group query returns nothing and JIRA is never touched.
        """
        importer = self._reimporter()
        importer.unchanged_items = []

        with patch("dojo.importers.default_reimporter.jira_services.push") as mock_push:
            importer.process_groups_for_all_findings()

        mock_push.assert_not_called()
