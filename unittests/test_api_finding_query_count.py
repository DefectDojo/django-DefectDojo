"""Verify the Finding list endpoint query count, ordering, and sort stability."""
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
        """Create findings sharing the same test so prefetch counts stay constant."""
        for i in range(count):
            Finding.objects.create(
                title=f"{prefix} Finding {i}", test=self.test_obj,
                reporter=self.user, severity="High",
                description="test", active=True, date=now().date(),
            )

    # ------------------------------------------------------------------
    # Point 5a: query count must not grow with data volume
    # ------------------------------------------------------------------
    def test_query_count_stable_across_pages(self):
        """Adding findings beyond the page size must not increase the per-page query count."""
        self._create_findings(self.PAGE_SIZE + 5, "batch1")

        with CaptureQueriesContext(connection) as ctx1:
            r1 = self.client.get(f"/api/v2/findings/?limit={self.PAGE_SIZE}")
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(len(r1.data["results"]), self.PAGE_SIZE)
        count_page1 = len(ctx1.captured_queries)

        # Double the total findings — page 1 should still be the same cost.
        self._create_findings(self.PAGE_SIZE + 5, "batch2")

        with CaptureQueriesContext(connection) as ctx2:
            r2 = self.client.get(f"/api/v2/findings/?limit={self.PAGE_SIZE}")
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(len(r2.data["results"]), self.PAGE_SIZE)
        count_page2 = len(ctx2.captured_queries)

        self.assertEqual(
            count_page1, count_page2,
            f"Query count changed from {count_page1} to {count_page2} when "
            f"doubling the total findings. The list endpoint should issue a "
            f"constant number of queries per page regardless of data volume.",
        )

    # ------------------------------------------------------------------
    # Point 5b: sorting by M2M annotation fields must not 500
    # ------------------------------------------------------------------
    def test_ordering_by_found_by(self):
        """?o=found_by must not raise a 500 (MultivaluedOrderingFilter annotation)."""
        self._create_findings(3, "o_fb")
        r = self.client.get("/api/v2/findings/?o=found_by")
        self.assertIn(r.status_code, (200,), msg=f"?o=found_by returned {r.status_code}")

    def test_ordering_by_reviewers(self):
        """?o=reviewers must not raise a 500 (MultivaluedOrderingFilter annotation)."""
        self._create_findings(3, "o_rv")
        r = self.client.get("/api/v2/findings/?o=reviewers")
        self.assertIn(r.status_code, (200,), msg=f"?o=reviewers returned {r.status_code}")

    def test_ordering_by_product_name(self):
        """?o=-test__engagement__product__name must work through the FK chain."""
        self._create_findings(3, "o_pn")
        r = self.client.get("/api/v2/findings/?o=-test__engagement__product__name")
        self.assertIn(r.status_code, (200,), msg=f"?o=-test__engagement__product__name returned {r.status_code}")

    # ------------------------------------------------------------------
    # Point 5c: ordering must be stable across consecutive pages
    # ------------------------------------------------------------------
    def test_ordering_consistent_across_pages(self):
        """Results on page 1 and page 2 must not overlap and must follow the same order."""
        # Create enough findings for two full pages with identical severity/date
        # so ties are common (default ordering: numerical_severity, -date, title).
        total = self.PAGE_SIZE * 2 + 5
        self._create_findings(total, "stab")

        r1 = self.client.get(f"/api/v2/findings/?limit={self.PAGE_SIZE}&offset=0")
        r2 = self.client.get(f"/api/v2/findings/?limit={self.PAGE_SIZE}&offset={self.PAGE_SIZE}")
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r2.status_code, 200)

        ids_page1 = [f["id"] for f in r1.data["results"]]
        ids_page2 = [f["id"] for f in r2.data["results"]]

        # Pages must not overlap.
        overlap = set(ids_page1) & set(ids_page2)
        self.assertEqual(
            len(overlap), 0,
            f"Pages 1 and 2 share {len(overlap)} finding IDs: {overlap}",
        )

        # Re-request page 1 — must return the same IDs in the same order.
        r1_again = self.client.get(f"/api/v2/findings/?limit={self.PAGE_SIZE}&offset=0")
        ids_page1_again = [f["id"] for f in r1_again.data["results"]]
        self.assertEqual(
            ids_page1, ids_page1_again,
            "Re-requesting page 1 returned different results.",
        )
