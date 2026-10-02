"""Verify the Finding list endpoint query count stays bounded as data grows."""
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils.timezone import now
from rest_framework.test import APITestCase

from dojo.models import (
    Development_Environment,
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)


class TestFindingListQueryCount(APITestCase):

    """Query count for /api/v2/findings/ must not grow with the number of findings."""

    PAGE_SIZE = 25

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(
            username="qc_user", is_staff=True, is_superuser=True,
        )
        cls.prod_type = Product_Type.objects.create(name="QC PT")
        cls.test_type = Test_Type.objects.create(name="QC TT")
        cls.env = Development_Environment.objects.create(name="QC Env")
        # Shared product/engagement/test so prefetch counts stay constant
        cls.product = Product.objects.create(
            name="QC Product", description="test", prod_type=cls.prod_type,
        )
        cls.eng = Engagement.objects.create(
            name="QC Eng", description="test", product=cls.product,
            target_start=now(), target_end=now(),
        )
        cls.test_obj = Test.objects.create(
            title="QC Test", description="test", engagement=cls.eng,
            test_type=cls.test_type, environment=cls.env,
            target_start=now(), target_end=now(),
        )

    def setUp(self):
        self.client.force_authenticate(user=self.user)

    def _create_findings(self, count, prefix):
        """Create findings all sharing the same test to keep prefetch counts stable."""
        for i in range(count):
            Finding.objects.create(
                title=f"{prefix} Finding {i}", test=self.test_obj,
                reporter=self.user, severity="High",
                description="test", active=True, date=now().date(),
            )

    def test_query_count_stable_across_pages(self):
        """Adding findings beyond the page size must not increase the per-page query count."""
        # Create more than one page of findings
        self._create_findings(self.PAGE_SIZE + 5, "batch1")

        with CaptureQueriesContext(connection) as ctx1:
            r1 = self.client.get(f"/api/v2/findings/?limit={self.PAGE_SIZE}")
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(len(r1.data["results"]), self.PAGE_SIZE)
        count_page1 = len(ctx1.captured_queries)

        # Double the total findings — page 1 should still be the same cost
        self._create_findings(self.PAGE_SIZE + 5, "batch2")

        with CaptureQueriesContext(connection) as ctx2:
            r2 = self.client.get(f"/api/v2/findings/?limit={self.PAGE_SIZE}")
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(len(r2.data["results"]), self.PAGE_SIZE)
        count_page2 = len(ctx2.captured_queries)

        # The query count must not grow: O(1) not O(N)
        self.assertEqual(
            count_page1, count_page2,
            f"Query count changed from {count_page1} to {count_page2} when "
            f"doubling the total findings. The list endpoint should issue a "
            f"constant number of queries per page regardless of data volume.",
        )
