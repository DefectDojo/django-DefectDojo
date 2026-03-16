"""
Regression test for: Product Metrics shows 0 Closed Findings while the findings
list displays them correctly.

Root cause: finding_queries() in dojo/product/views.py used end_date (derived from
the latest finding discovery date, built as midnight 00:00:00) as the upper bound
for mitigated__range. This made no semantic sense - a finding can be closed at any
time after discovery, so using the discovery date as the cutoff for mitigated is
incorrect.

Fix: replace end_date with timezone.now() as the upper bound so any finding closed
up to the current moment is counted.
"""

import zoneinfo
from datetime import date, datetime

from django.test import RequestFactory

from dojo.models import Engagement, Finding, Product, Product_Type, Test, Test_Type, User
from dojo.product.views import finding_queries

from .dojo_test_case import DojoTestCase

UTC = zoneinfo.ZoneInfo("UTC")


class ProductMetricsClosedCountTest(DojoTestCase):

    """Regression tests for closed finding counter in Product Metrics."""

    def setUp(self):
        self.user = User.objects.create_superuser(username="admin_regression", password="test")  # noqa: S106
        self.product_type = Product_Type.objects.create(name="Regression PT")
        self.product = Product.objects.create(
            name="Regression Product",
            prod_type=self.product_type,
            description="Regression test product",
        )
        self.engagement = Engagement.objects.create(
            name="Regression Eng",
            product=self.product,
            target_start=date(2024, 1, 1),
            target_end=date(2024, 12, 31),
        )
        self.test_type, _ = Test_Type.objects.get_or_create(name="Manual")
        self.test = Test.objects.create(
            engagement=self.engagement,
            test_type=self.test_type,
            target_start=datetime(2024, 1, 1, tzinfo=UTC),
            target_end=datetime(2024, 12, 31, tzinfo=UTC),
        )
        # date=7 corresponds to "Any date" in MetricsDateRangeFilter
        self.request = RequestFactory().get(f"/product/{self.product.id}/metrics", {"date": "7"})
        self.request.user = self.user

    def _make_closed(self, title, discovery_date, mitigated_dt, severity="High"):
        return Finding.objects.create(
            title=title,
            test=self.test,
            severity=severity,
            active=False,
            is_mitigated=True,
            date=discovery_date,
            mitigated=mitigated_dt,
            reporter=self.user,
            verified=True,
        )

    def test_closed_finding_same_day_after_midnight_is_counted(self):
        """
        A finding discovered on day X and closed on day X at 10:00 must appear
        in the closed counter. Before the fix end_date was derived from the latest
        discovery date as midnight, so this finding was silently excluded.
        """
        discovery = date(2024, 6, 15)
        # closed on the same day but well after midnight
        mitigated = datetime(2024, 6, 15, 10, 30, tzinfo=UTC)
        self._make_closed("Closed same-day after midnight", discovery, mitigated)

        filters = finding_queries(self.request, self.product)
        closed_ids = list(filters["closed"].values_list("id", flat=True))
        self.assertEqual(len(closed_ids), 1, "Expected exactly 1 closed finding in metrics")

    def test_closed_finding_on_same_day_as_end_date_is_counted(self):
        """
        A finding with discovery date in the past but closed recently must appear
        in the closed counter. Before the fix end_date was the latest discovery date
        (midnight), so findings closed after that date were excluded.
        """
        today = date(2025, 6, 15)
        # open finding - sets end_date to today
        Finding.objects.create(
            title="Open Finding - sets end_date",
            test=self.test, severity="Low",
            active=True, is_mitigated=False,
            date=today, reporter=self.user,
        )
        # closed finding - mitigated today at 10:00 (after midnight)
        closed = self._make_closed(
            "Closed same day as end_date",
            date(2024, 11, 27),
            datetime(2025, 6, 15, 10, 0, tzinfo=UTC),
        )

        filters = finding_queries(self.request, self.product)
        closed_ids = list(filters["closed"].values_list("id", flat=True))
        self.assertIn(
            closed.id, closed_ids,
            "Finding mitigated on the same day as end_date (but after midnight) must appear in closed metrics",
        )

    def test_closed_count_matches_findings_list_count(self):
        """
        All closed findings whose mitigated date falls within [start_date, end_date_eod]
        must be counted.  Specifically, findings closed on the same day as end_date
        at any time (including 23:59) must appear.
        """
        # All three findings have the same discovery date, so end_date = 2024-03-01 23:59:59
        self._make_closed("F1 - closed at 00:01", date(2024, 3, 1), datetime(2024, 3, 1, 0, 1, tzinfo=UTC))
        self._make_closed("F2 - closed at 14:00", date(2024, 3, 1), datetime(2024, 3, 1, 14, 0, tzinfo=UTC))
        self._make_closed("F3 - closed at 23:58", date(2024, 3, 1), datetime(2024, 3, 1, 23, 58, tzinfo=UTC))

        filters = finding_queries(self.request, self.product)
        metrics_count = filters["closed"].count()

        self.assertEqual(
            metrics_count,
            3,
            f"All 3 findings closed on end_date must be counted, got {metrics_count}",
        )
