# Regression: auto finding grouping on (re)import cost O(groups x findings): every newly created
# group re-read and hydrated the whole test to look for old same-name findings.
from contextlib import contextmanager

from crum import impersonate
from django.db import connection
from django.db.models.signals import post_init
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from parameterized import parameterized

from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import (
    Development_Environment,
    Engagement,
    Finding,
    Finding_Group,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
)

from .dojo_test_case import DojoTestCase

SCAN_TYPE = "Generic Findings Import"


@contextmanager
def count_hydrated_findings():
    """Count Finding instances built from rows (the Python cost the alerts showed)."""
    counter = {"n": 0}

    def on_init(sender, instance, **kwargs):
        counter["n"] += 1

    post_init.connect(on_init, sender=Finding, weak=False, dispatch_uid="auto_group_hydration_counter")
    try:
        yield counter
    finally:
        post_init.disconnect(sender=Finding, dispatch_uid="auto_group_hydration_counter")


class TestImportersAutoFindingGroups(DojoTestCase):

    """
    process_groups_for_all_findings() groups a whole (re)import. For every group it had to
    create, it used to load every finding of the test and compute each one's group name in
    Python, then add matching old findings one M2M write at a time: a reimport with a few
    hundred titles into a test of a few thousand findings spent minutes building Finding rows.

    Grouping is now set-based: the test's findings are read once (only for names whose group
    is new), existing groups in one query, new groups and memberships in bulk. What lands in
    the database must not change, so the behavior tests below pin today's semantics.
    """

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="auto_group_bulk")
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        product, _ = Product.objects.get_or_create(name="TestImportersAutoFindingGroups", description="Test", prod_type=product_type)
        engagement = Engagement.objects.create(
            name="Auto Group Engagement", product=product, target_start=timezone.now(), target_end=timezone.now(),
        )
        test_type, _ = Test_Type.objects.get_or_create(name=SCAN_TYPE)
        self.test = Test.objects.create(
            engagement=engagement, test_type=test_type, scan_type=SCAN_TYPE,
            target_start=timezone.now(), target_end=timezone.now(),
        )

    def _findings(self, titles):
        findings = Finding.objects.bulk_create([
            Finding(test=self.test, title=title, severity="High", reporter=self.user, numerical_severity="S1")
            for title in titles
        ])
        # bulk_create hands back the same instances; re-read them so they look like what the importer holds
        return list(Finding.objects.filter(id__in=[f.id for f in findings]).order_by("id"))

    def _reimporter(self, groups, *, create_all=True):
        reimporter = DefaultReImporter(
            test=self.test, user=self.user, lead=self.user, scan_date=None, environment=self.environment,
            active=True, verified=False, scan_type=SCAN_TYPE, close_old_findings=False,
            group_by="finding_title", create_finding_groups_for_all_findings=create_all,
        )
        reimporter.group_names_to_findings_dict = groups
        reimporter.reactivated_items = []
        reimporter.unchanged_items = []
        return reimporter

    def _group(self, groups, *, create_all=True):
        reimporter = self._reimporter(groups, create_all=create_all)
        # an import runs as its user; new groups record them as creator
        with impersonate(self.user):
            reimporter.process_groups_for_all_findings()

    @staticmethod
    def _name(title):
        return f"Findings in: {title}"

    def _seed(self, group_count, *, new_per_group=2, old_per_group=1):
        """group_count titles, each with old ungrouped findings already in the test and new ones being imported."""
        titles = [f"Title {i:04d}" for i in range(group_count)]
        self._findings([t for t in titles for _ in range(old_per_group)])
        new = self._findings([t for t in titles for _ in range(new_per_group)])
        groups = {}
        for finding in new:
            groups.setdefault(self._name(finding.title), []).append(finding)
        return groups

    def _membership(self):
        return {
            group.name: sorted(group.findings.values_list("id", flat=True))
            for group in Finding_Group.objects.filter(test=self.test)
        }

    def test_grouping_cost_does_not_grow_with_group_count(self):
        measured = {}
        for group_count in (4, 24):
            Finding.objects.filter(test=self.test).delete()
            Finding_Group.objects.filter(test=self.test).delete()
            reimporter = self._reimporter(self._seed(group_count))
            with impersonate(self.user), count_hydrated_findings() as hydrated, CaptureQueriesContext(connection) as queries:
                reimporter.process_groups_for_all_findings()
            groups = Finding_Group.objects.filter(test=self.test).count()
            self.assertEqual(group_count, groups, msg=f"expected {group_count} groups, persisted {groups}")
            measured[group_count] = (len(queries), hydrated["n"], Finding.objects.filter(test=self.test).count())

        (small_queries, _, _), (large_queries, large_hydrated, large_findings) = measured[4], measured[24]
        with self.subTest("queries"):
            self.assertEqual(
                small_queries, large_queries,
                msg=f"grouping queries grew with the group count: 4 groups={small_queries}, 24 groups={large_queries}",
            )
        with self.subTest("hydrated findings"):
            # each finding in the test may be read once, never once per new group
            self.assertLessEqual(
                large_hydrated, large_findings,
                msg=f"hydrated {large_hydrated} Finding rows for a test of {large_findings} findings across 24 new groups",
            )

    def test_new_group_pulls_in_old_ungrouped_same_name_findings(self):
        old_same = self._findings(["Shared"])[0]
        old_other = self._findings(["Unrelated"])[0]
        new = self._findings(["Shared", "Shared"])

        self._group({self._name("Shared"): new})

        membership = self._membership()
        self.assertEqual(
            {self._name("Shared"): sorted([old_same.id, *(f.id for f in new)])}, membership,
            msg=f"old same-name finding {old_same.id} must join the new group; {old_other.id} must not; persisted {membership}",
        )
        group = Finding_Group.objects.get(test=self.test)
        self.assertEqual(self.user, group.creator, msg=f"persisted creator={group.creator}")

    def test_existing_group_takes_new_findings_without_pulling_old_ones(self):
        old = self._findings(["Shared"])[0]
        existing = Finding_Group.objects.create(test=self.test, name=self._name("Shared"), creator=self.user)
        new = self._findings(["Shared"])

        self._group({self._name("Shared"): new})

        membership = self._membership()
        self.assertEqual(
            {existing.name: [new[0].id]}, membership,
            msg=f"an existing group only gains the imported findings (old {old.id} stays out); persisted {membership}",
        )

    def test_reuses_oldest_of_duplicate_same_name_groups(self):
        oldest = Finding_Group.objects.create(test=self.test, name=self._name("Dup"), creator=self.user)
        newer = Finding_Group.objects.create(test=self.test, name=self._name("Dup"), creator=self.user)
        new = self._findings(["Dup"])

        self._group({self._name("Dup"): new})

        self.assertEqual([new[0].id], list(oldest.findings.values_list("id", flat=True)), msg="oldest group gets the finding")
        self.assertEqual([], list(newer.findings.values_list("id", flat=True)), msg="newer duplicate stays empty")

    # One older same-name finding, and two: the per-name loop left the imported finding out of
    # the group it created when two or more older findings shared its name (its `created` flag
    # was overwritten by the second lookup). The imported finding belongs in the group either way.
    @parameterized.expand([(1,), (2,)])
    def test_lone_finding_without_create_all(self, old_count):
        # create_finding_groups_for_all_findings=False: a lone finding only forms a group when
        # another finding of the test shares its name, and otherwise stays ungrouped.
        old = self._findings(["Paired"] * old_count)
        paired = self._findings(["Paired"])
        alone = self._findings(["Alone"])

        self._group({self._name("Paired"): paired, self._name("Alone"): alone}, create_all=False)

        membership = self._membership()
        self.assertEqual(
            {self._name("Paired"): sorted([*(f.id for f in old), paired[0].id])}, membership,
            msg=f"expected only the paired group, holding the imported finding {paired[0].id}; persisted {membership}",
        )

    def test_names_truncated_to_the_same_group_share_it(self):
        # Group names are stored cut to 255 characters, so two titles that only differ past
        # that point land in one group, the same way the per-name loop resolved them.
        prefix = "x" * 300
        first = self._findings([prefix + "a"])
        second = self._findings([prefix + "b"])

        self._group({self._name(prefix + "a"): first, self._name(prefix + "b"): second})

        membership = self._membership()
        self.assertEqual(
            {self._name(prefix)[:255]: sorted([first[0].id, second[0].id])}, membership,
            msg=f"persisted {membership}",
        )
