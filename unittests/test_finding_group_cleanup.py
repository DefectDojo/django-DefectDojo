from django.utils.timezone import now

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


class TestFindingGroupCleanup(DojoTestCase):

    """
    Finding_Group.findings is a ManyToManyField, so deleting the findings in a group
    only removed the through rows and left the group behind — visible in the UI and
    still carrying its JIRA link, with no way to remove it via the API.
    See #11044 and #11327.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(username="group-cleanup-user")
        cls.prod_type = Product_Type.objects.create(name="Group Cleanup Type")
        cls.product = Product.objects.create(
            name="Group Cleanup Product", prod_type=cls.prod_type, description="x",
        )
        cls.engagement = Engagement.objects.create(
            name="Group Cleanup Engagement",
            product=cls.product,
            target_start=now(),
            target_end=now(),
        )
        cls.test_type = Test_Type.objects.create(name="Group Cleanup Test Type")
        cls.environment = Development_Environment.objects.create(name="Group Cleanup Env")

    def _make_test(self):
        return Test.objects.create(
            engagement=self.engagement,
            test_type=self.test_type,
            environment=self.environment,
            target_start=now(),
            target_end=now(),
        )

    def _make_group(self, test, findings):
        group = Finding_Group.objects.create(
            name="a group", test=test, creator=self.user,
        )
        group.findings.set(findings)
        return group

    def _make_finding(self, test, title):
        return Finding.objects.create(
            title=title, test=test, severity="High", reporter=self.user,
        )

    def test_group_is_removed_once_its_last_finding_is_deleted(self):
        test = self._make_test()
        finding = self._make_finding(test, "only member")
        group = self._make_group(test, [finding])

        finding.delete()

        self.assertFalse(
            Finding_Group.objects.filter(id=group.id).exists(),
            "the group outlived the last finding in it",
        )

    def test_group_is_kept_while_it_still_has_findings(self):
        test = self._make_test()
        first = self._make_finding(test, "first member")
        second = self._make_finding(test, "second member")
        group = self._make_group(test, [first, second])

        first.delete()

        group.refresh_from_db()
        self.assertEqual([second.id], [f.id for f in group.findings.all()])

    def test_deleting_every_finding_in_turn_removes_the_group(self):
        test = self._make_test()
        first = self._make_finding(test, "first member")
        second = self._make_finding(test, "second member")
        group = self._make_group(test, [first, second])

        first.delete()
        self.assertTrue(Finding_Group.objects.filter(id=group.id).exists())
        second.delete()
        self.assertFalse(Finding_Group.objects.filter(id=group.id).exists())

    def test_ungrouped_finding_delete_leaves_other_groups_alone(self):
        test = self._make_test()
        grouped = self._make_finding(test, "grouped")
        ungrouped = self._make_finding(test, "ungrouped")
        group = self._make_group(test, [grouped])

        ungrouped.delete()

        self.assertTrue(Finding_Group.objects.filter(id=group.id).exists())

    def test_deleting_the_test_still_removes_its_groups(self):
        """Groups cascade with the Test; the new cleanup must not trip over that."""
        test = self._make_test()
        finding = self._make_finding(test, "member")
        group = self._make_group(test, [finding])

        test.delete()

        self.assertFalse(Finding_Group.objects.filter(id=group.id).exists())
        self.assertFalse(Finding.objects.filter(id=finding.id).exists())
