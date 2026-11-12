import json

from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.renderers import JSONRenderer
from rest_framework.test import APIClient, APIRequestFactory, APITestCase

from dojo.jira.models import JIRA_Instance, JIRA_Issue, JIRA_Project
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding_Group,
    Test,
    Test_Type,
)
from dojo.test.api.serializer import TestSerializer
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class TestListQueryCountTest(APITestCase):

    """
    Regression test for an N+1 on ``GET /api/v2/tests/`` (view ``test-list``).

    ``TestSerializer`` reads ``test_type`` three times per row (``test_type_name``,
    ``deduplication_algorithm``, ``hash_code_fields``) and serializes each test's
    tags and finding groups (with their JIRA issue). With no ``select_related`` /
    ``prefetch_related`` for those relations on the viewset queryset the query
    count grew linearly with the number of tests returned, so listing a page of
    tests produced hundreds of queries on large instances.

    The list serialization must issue a constant number of queries regardless of
    how many tests are returned.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.engagement = Engagement.objects.get(id=1)
        self.test_type = Test_Type.objects.get(id=1)
        self.admin = Dojo_User.objects.get(username="admin")

    def _create_tests(self, count, prefix):
        # Use timezone-aware datetimes: Test.target_start/target_end are
        # DateTimeFields and a naive value raises a RuntimeWarning under
        # USE_TZ (treated as an error in CI).
        now = timezone.now()
        for i in range(count):
            test = Test.objects.create(
                engagement=self.engagement,
                test_type=self.test_type,
                target_start=now,
                target_end=now,
            )
            # Tags and a finding group are both serialized per test, so they
            # exercise the prefetches the fix adds.
            test.tags = f"{prefix}_tag_a_{i}, {prefix}_tag_b"
            test.save()
            Finding_Group.objects.create(
                name=f"{prefix}_group_{i}",
                test=test,
                creator=self.admin,
            )

    def test_test_list_query_count_is_constant(self):
        url = reverse("test-list")

        # Warm up content-type / permission caches so they don't skew the first
        # measured request relative to the second.
        self.client.get(url, {"limit": 1000})

        self._create_tests(8, "nplus1_batch_a")
        with CaptureQueriesContext(connection) as ctx_a:
            response_a = self.client.get(url, {"limit": 1000})
        self.assertEqual(response_a.status_code, 200, response_a.content[:1000])
        queries_a = len(ctx_a)

        self._create_tests(8, "nplus1_batch_b")
        with CaptureQueriesContext(connection) as ctx_b:
            response_b = self.client.get(url, {"limit": 1000})
        self.assertEqual(response_b.status_code, 200, response_b.content[:1000])
        queries_b = len(ctx_b)

        # Sanity: the second response really does serialize the extra 8 tests.
        self.assertEqual(
            response_b.json()["count"],
            response_a.json()["count"] + 8,
        )

        self.assertEqual(
            queries_a,
            queries_b,
            f"GET {url} query count grows with the number of tests (N+1): "
            f"{queries_a} queries for {response_a.json()['count']} tests vs "
            f"{queries_b} queries for {response_b.json()['count']} tests.",
        )

    def test_test_list_still_serializes_related_fields(self):
        """The prefetch/select_related change must not alter serialized output."""
        url = reverse("test-list")
        self._create_tests(1, "nplus1_related")
        response = self.client.get(url, {"limit": 1000})
        self.assertEqual(response.status_code, 200, response.content[:1000])
        created = next(
            t for t in response.json()["results"]
            if t["test_type_name"] == self.test_type.name
            and "nplus1_related_tag_b" in t.get("tags", [])
        )
        for field in (
            "test_type",
            "test_type_name",
            "deduplication_algorithm",
            "hash_code_fields",
            "tags",
            "finding_groups",
        ):
            self.assertIn(field, created, created)
        self.assertTrue(
            any(g["name"] == "nplus1_related_group_0" for g in created["finding_groups"]),
            created["finding_groups"],
        )


@versioned_fixtures
class TestFindingGroupJiraQueryCountTest(DojoTestCase):

    """
    Regression test for ``GET /api/v2/tests/`` and ``GET /api/v2/tests/{id}/`` with JIRA enabled.

    ``TestSerializer`` nests each finding group's JIRA issue, and the issue's ``url`` reads the issue's
    ``jira_project`` and that project's ``jira_instance``. The viewset prefetched the groups' issues but not
    the two relations behind ``url``, so each group with a JIRA issue cost two more queries.

    The query count must not grow with the number of finding groups in the test, and the payload must be the
    one the serializer builds from an instance with nothing prefetched.
    """

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        cls.admin = Dojo_User.objects.get(username="admin")
        engagement = Engagement.objects.get(id=1)
        now = timezone.now()
        cls.test = Test.objects.create(
            engagement=engagement, test_type=Test_Type.objects.get(id=1), target_start=now, target_end=now,
        )
        instance = JIRA_Instance.objects.create(
            configuration_name="test finding groups",
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
        cls.jira_project = JIRA_Project.objects.create(
            jira_instance=instance, project_key="TGRP", product=engagement.product,
        )
        # A group with no JIRA issue stays in the test throughout, so the payload must carry it as null
        Finding_Group.objects.create(name="group without issue", test=cls.test, creator=cls.admin)

    def setUp(self):
        super().setUp()
        token, _ = Token.objects.get_or_create(user=self.admin)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        # The issue url is resolved through jira_project and jira_instance only while JIRA is enabled
        self.system_settings(enable_jira=True)

    def _add_group(self, index):
        group = Finding_Group.objects.create(name=f"group {index}", test=self.test, creator=self.admin)
        JIRA_Issue.objects.create(
            jira_id=f"{index}", jira_key=f"TGRP-{index}", finding_group=group, jira_project=self.jira_project,
        )

    def _get(self, url, params=None):
        with CaptureQueriesContext(connection) as queries:
            response = self.client.get(url, params, format="json")
        self.assertEqual(response.status_code, 200, response.content[:1000])
        return len(queries.captured_queries), response.json()

    def _assert_flat(self, url, params=None):
        self._add_group(0)
        self._get(url, params)  # warm the content type and permission caches
        one_group, _ = self._get(url, params)
        for index in range(1, 6):
            self._add_group(index)
        six_groups, body = self._get(url, params)
        self.assertEqual(
            one_group,
            six_groups,
            f"GET {url} cost {one_group} queries with 1 JIRA-linked finding group and {six_groups} with 6",
        )
        return body

    def _assert_groups(self, test_body):
        groups = {group["name"]: group["jira_issue"] for group in test_body["finding_groups"]}
        self.assertIsNone(groups.pop("group without issue"), "a group with no JIRA issue should carry null")
        self.assertEqual(
            sorted((issue["jira_key"], issue["url"]) for issue in groups.values()),
            [(f"TGRP-{index}", f"https://jira.test/browse/TGRP-{index}") for index in range(6)],
            "every finding group should be serialized with its JIRA issue and that issue's url",
        )

    def _unprefetched_body(self):
        # What the serializer builds when every relation is read lazily: the payload the prefetch must not change
        request = APIRequestFactory().get("/")
        request.user = self.admin
        serializer = TestSerializer(Test.objects.get(pk=self.test.pk), context={"request": request})
        return json.loads(JSONRenderer().render(serializer.data))

    def test_detail_query_count_does_not_grow_per_jira_finding_group(self):
        body = self._assert_flat(reverse("test-detail", args=[self.test.pk]))
        self._assert_groups(body)
        # The detail view adds the ?prefetch= expansion beside the serialized test
        self.assertEqual(body.pop("prefetch"), {})
        self.assertEqual(body, self._unprefetched_body())

    def test_list_query_count_does_not_grow_per_jira_finding_group(self):
        body = self._assert_flat(reverse("test-list"), {"id": self.test.pk})
        self.assertEqual(body["count"], 1)
        self._assert_groups(body["results"][0])
        self.assertEqual(body["results"][0], self._unprefetched_body())

    def test_jira_disabled_loads_no_jira_project_or_instance(self):
        """With JIRA off an issue's url is null without its project or instance being read, so neither is loaded."""
        self.system_settings(enable_jira=False)
        for index in range(6):
            self._add_group(index)
        for url, params in (
            (reverse("test-detail", args=[self.test.pk]), None),
            (reverse("test-list"), {"id": self.test.pk}),
        ):
            self.client.get(url, params, format="json")  # warm the content type and permission caches
            with CaptureQueriesContext(connection) as queries:
                response = self.client.get(url, params, format="json")
            self.assertEqual(response.status_code, 200, response.content[:1000])
            jira_reads = [
                query["sql"] for query in queries.captured_queries
                if '"dojo_jira_project"' in query["sql"] or '"dojo_jira_instance"' in query["sql"]
            ]
            self.assertEqual(jira_reads, [], f"GET {url} read a JIRA project or instance with JIRA disabled")
            body = response.json()
            test_body = body["results"][0] if "results" in body else body
            test_body.pop("prefetch", None)
            self.assertEqual(
                {group["jira_issue"]["url"] for group in test_body["finding_groups"] if group["jira_issue"]}, {None},
            )
            self.assertEqual(test_body, self._unprefetched_body())
