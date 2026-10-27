"""
Regression test for ``?prefetch=test`` on a finding.

``TestSerializer`` nests every finding group in the test, each with its JIRA
issue. The prefetcher serializes a single related object (a finding's test) from
the finding's own instance, so the batched lookups it applies to the authorized
queryset never reached it, and each group's ``jira_issue`` was read with its own
query. A finding retrieve in a test with many groups ran one query per group:
about 1,450 queries for a single finding.

The test pins that the query count of ``?prefetch=test`` does not grow with the
number of finding groups in the test, and that the groups and their JIRA issues
are still in the payload.
"""

from types import SimpleNamespace

from crum import impersonate
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils.timezone import now

from dojo.api_v2.prefetch import prefetcher as prefetcher_module
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Finding_Group,
    JIRA_Issue,
    Product,
    Product_Type,
    Test,
    Test_Type,
)
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class PrefetchTestFindingGroupsTest(DojoTestCase):

    """``?prefetch=test`` must cost the same for a test with 1 finding group as for 6."""

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="PrefetchTestGroups PT")
        test_type, _ = Test_Type.objects.get_or_create(name="PrefetchTestGroups Scan")
        product = Product.objects.create(
            name="PrefetchTestGroups Product",
            description="test finding group prefetch",
            prod_type=prod_type,
        )
        engagement = Engagement.objects.create(
            name="PrefetchTestGroups Engagement",
            product=product,
            target_start=now(),
            target_end=now(),
        )
        cls.admin = Dojo_User.objects.get(username="admin")
        cls.test = Test.objects.create(
            engagement=engagement,
            test_type=test_type,
            target_start=now(),
            target_end=now(),
            lead=cls.admin,
        )
        cls.finding = Finding.objects.create(
            title="PrefetchTestGroups Finding",
            test=cls.test,
            reporter=cls.admin,
            severity="Info",
            numerical_severity="S4",
        )

    def _add_group(self, index):
        group = Finding_Group.objects.create(name=f"group {index}", test=self.test, creator=self.admin)
        JIRA_Issue.objects.create(jira_id=f"{index}", jira_key=f"GRP-{index}", finding_group=group)

    def _prefetch_test(self):
        # A fresh instance each time, so nothing loaded by an earlier call is reused
        finding = Finding.objects.select_related("test").get(pk=self.finding.pk)
        prefetcher = prefetcher_module._Prefetcher(request=SimpleNamespace(user=self.admin))
        with impersonate(self.admin), CaptureQueriesContext(connection) as queries:
            prefetcher._prefetch(finding, ["test"])
        return len(queries.captured_queries), prefetcher.prefetched_data

    def test_prefetch_test_query_count_does_not_grow_per_finding_group(self):
        self._add_group(0)
        one_group, _ = self._prefetch_test()
        for index in range(1, 6):
            self._add_group(index)
        six_groups, data = self._prefetch_test()

        groups = data["test"][self.test.pk]["finding_groups"]
        self.assertEqual(
            sorted(group["jira_issue"]["jira_key"] for group in groups),
            [f"GRP-{index}" for index in range(6)],
            "every finding group in the test should be serialized with its JIRA issue",
        )
        self.assertEqual(
            one_group,
            six_groups,
            f"?prefetch=test cost {one_group} queries with 1 finding group and {six_groups} with 6",
        )
