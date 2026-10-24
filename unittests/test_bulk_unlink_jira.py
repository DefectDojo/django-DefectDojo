import datetime
from unittest.mock import patch

from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.urls import reverse
from django.utils import timezone

from dojo.authorization.models import Product_Type_Member, Role
from dojo.authorization.roles_permissions import Roles
from dojo.jira.models import JIRA_Instance, JIRA_Issue, JIRA_Project
from dojo.models import Engagement, Finding, Finding_Group, Product, Product_Type, Test, Test_Type

from .dojo_test_case import DojoTestCase


class TestBulkUnlinkFromJira(DojoTestCase):

    """Bulk edit's Unlink from Jira removes the DefectDojo link and leaves the Jira issue alone."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User(username="bulk-unlink", is_staff=True)
        cls.user.set_password("testpass")
        cls.user.save()
        product_type = Product_Type.objects.create(name="Bulk Unlink")
        cls.product = Product.objects.create(prod_type=product_type, name="Bulk Unlink Product", description="d")
        Product_Type_Member.objects.create(product_type=product_type, user=cls.user, role=Role.objects.get(id=Roles.Owner))
        engagement = Engagement.objects.create(
            product=cls.product,
            target_start=timezone.now(),
            target_end=timezone.now() + datetime.timedelta(days=30),
        )
        cls.test = Test.objects.create(
            engagement=engagement,
            test_type=Test_Type.objects.create(name="Bulk Unlink Test", static_tool=True),
            target_start=timezone.now(),
            target_end=timezone.now() + datetime.timedelta(days=1),
        )
        cls.linked = cls._finding("linked")
        cls.other = cls._finding("other")
        cls.never_linked = cls._finding("never linked")
        instance = JIRA_Instance.objects.create(
            configuration_name="bulk unlink",
            url="https://jira.test",
            username="dojo",
            password="secret",  # noqa: S106 -- test-only Jira instance
            default_issue_type="Bug",
            epic_name_id=10011,
            open_status_key=11,
            close_status_key=21,
            info_mapping_severity="Lowest",
            low_mapping_severity="Low",
            medium_mapping_severity="Medium",
            high_mapping_severity="High",
            critical_mapping_severity="Highest",
        )
        cls.jira_project = JIRA_Project.objects.create(jira_instance=instance, project_key="OLD", product=cls.product)

    @classmethod
    def _finding(cls, title):
        return Finding.objects.create(
            test=cls.test, title=title, severity="High", active=True, verified=True, reporter=cls.user,
            numerical_severity="S1",
        )

    def setUp(self):
        self.system_settings(enable_jira=True)
        self.client.force_login(self.user)
        self.linked_issue = self._issue("OLD-1", finding=self.linked)
        self.other_issue = self._issue("OLD-2", finding=self.other)

    def _issue(self, key, finding=None, finding_group=None):
        return JIRA_Issue.objects.create(
            jira_project=self.jira_project, jira_id=key, jira_key=key, finding=finding, finding_group=finding_group,
        )

    def _bulk_edit(self, findings, **extra):
        data = {
            "finding_to_update": [str(finding.id) for finding in findings],
            "return_url": reverse("view_test", args=(self.test.id,)),
            "unlink_from_jira": "on",
            **extra,
        }
        response = self.client.post(reverse("finding_bulk_update_all"), data, follow=True)
        return [str(message) for message in get_messages(response.wsgi_request)]

    def test_unlinks_only_the_selected_findings(self):
        messages = self._bulk_edit([self.linked, self.never_linked])

        self.assertFalse(JIRA_Issue.objects.filter(id=self.linked_issue.id).exists())
        self.assertTrue(JIRA_Issue.objects.filter(id=self.other_issue.id).exists())
        self.assertIn("1 finding unlinked from JIRA successfully", messages)

    def test_unlinks_the_finding_group_of_a_selected_finding(self):
        group = Finding_Group.objects.create(name="component: openssl", test=self.test, creator=self.user)
        group.findings.add(self.never_linked)
        group_issue = self._issue("OLD-3", finding_group=group)

        messages = self._bulk_edit([self.never_linked])

        self.assertFalse(JIRA_Issue.objects.filter(id=group_issue.id).exists())
        self.assertIn("1 finding group unlinked from JIRA successfully", messages)

    def test_nothing_linked_is_reported(self):
        messages = self._bulk_edit([self.never_linked])

        self.assertIn("None of the selected findings are linked to a JIRA issue", messages)
        self.assertNotIn("Bulk update of 1 findings was successful.", messages)

    def test_a_user_who_cannot_edit_is_told_why_not_that_nothing_is_linked(self):
        outsider = User.objects.create(username="bulk-unlink-outsider", is_staff=False)
        self.client.force_login(outsider)

        messages = self._bulk_edit([self.linked])

        self.assertTrue(JIRA_Issue.objects.filter(id=self.linked_issue.id).exists())
        self.assertIn("Skipped update of 1 findings because you are not authorized.", messages)
        self.assertNotIn("None of the selected findings are linked to a JIRA issue", messages)

    def test_jira_disabled_ignores_the_unlink(self):
        self.system_settings(enable_jira=False)

        self._bulk_edit([self.linked])

        self.assertTrue(JIRA_Issue.objects.filter(id=self.linked_issue.id).exists())

    def test_unlink_runs_before_the_push(self):
        """The push sees no issue, so it creates one in the current project rather than updating OLD-1."""
        seen = []

        def record_push(obj, *args, **kwargs):
            seen.append((obj.id, JIRA_Issue.objects.filter(finding=obj).exists()))
            return True, "pushed"

        with patch("dojo.jira.services.push", side_effect=record_push):
            self._bulk_edit([self.linked], push_to_jira="on")

        self.assertIn((self.linked.id, False), seen)

    def test_without_the_checkbox_nothing_is_unlinked(self):
        data = {
            "finding_to_update": [str(self.linked.id)],
            "return_url": reverse("view_test", args=(self.test.id,)),
            "severity": "Low",
        }
        self.client.post(reverse("finding_bulk_update_all"), data, follow=True)

        self.assertTrue(JIRA_Issue.objects.filter(id=self.linked_issue.id).exists())
