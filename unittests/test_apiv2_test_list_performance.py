from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

from dojo.models import (
    Dojo_User,
    Engagement,
    Finding_Group,
    Test,
    Test_Type,
)
from unittests.dojo_test_case import versioned_fixtures


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
