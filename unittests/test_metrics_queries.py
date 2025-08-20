"""Tests for metrics database queries"""

import zoneinfo
from datetime import date, datetime
from unittest.mock import patch

from django.test import RequestFactory
from django.urls import reverse

from dojo.metrics import utils
from dojo.models import Product_Type, User

from .dojo_test_case import DojoTestCase


class MockMessages:
    def add(*args, **kwargs):
        pass


####
# Test Findings data
####
FINDING_1 = {"id": 4, "date": date(2018, 1, 1), "severity": "High", "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 2, "out_of_scope": False, "risk_accepted": False, "under_review": False, "is_mitigated": False, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0"}
FINDING_2 = {"id": 5, "date": date(2018, 1, 1), "severity": "High", "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 2, "out_of_scope": False, "risk_accepted": False, "under_review": False, "is_mitigated": False, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0"}
FINDING_3 = {"id": 6, "date": date(2018, 1, 1), "severity": "High", "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 2, "out_of_scope": False, "risk_accepted": False, "under_review": False, "is_mitigated": False, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0"}
FINDING_4 = {"id": 7, "date": date(2017, 12, 31), "severity": "High", "active": False, "verified": False, "false_p": False, "duplicate": False, "duplicate_finding_id": None, "out_of_scope": False, "risk_accepted": False, "under_review": False, "is_mitigated": False, "mitigated": None, "mitigated_by_id": None, "reporter_id": 2, "numerical_severity": "S0"}
FINDING_5 = {"id": 24, "date": date(2018, 1, 1), "severity": "Low", "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 22, "out_of_scope": False, "risk_accepted": False, "under_review": False, "is_mitigated": False, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0"}
FINDING_6 = {"id": 125, "date": date(2018, 1, 1), "severity": "Low", "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": None, "out_of_scope": False, "risk_accepted": False, "under_review": False, "is_mitigated": False, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0"}
FINDING_7 = {"id": 225, "date": date(2018, 1, 1), "severity": "Low", "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 224, "out_of_scope": False, "risk_accepted": False, "under_review": False, "is_mitigated": False, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0"}
FINDING_8 = {"id": 240, "date": date(2018, 1, 1), "severity": "High", "active": True, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 2, "out_of_scope": False, "risk_accepted": False, "under_review": False, "is_mitigated": False, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0"}
FINDING_9 = {"id": 241, "date": date(2018, 1, 1), "severity": "High", "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 2, "out_of_scope": False, "risk_accepted": True, "under_review": False, "is_mitigated": False, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0"}
FINDING_10 = {"id": 242, "date": date(2018, 1, 1), "severity": "High", "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 2, "out_of_scope": False, "risk_accepted": True, "under_review": False, "is_mitigated": False, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0"}
FINDING_11 = {"id": 243, "date": date(2017, 12, 31), "severity": "High", "active": False, "verified": False, "false_p": False, "duplicate": False, "duplicate_finding_id": None, "out_of_scope": False, "risk_accepted": True, "under_review": False, "is_mitigated": True, "mitigated": None, "mitigated_by_id": None, "reporter_id": 2, "numerical_severity": "S0"}
FINDING_12 = {"id": 244, "date": date(2017, 12, 29), "severity": "Low", "active": True, "verified": True, "false_p": False, "duplicate": False, "duplicate_finding_id": None, "out_of_scope": False, "risk_accepted": False, "under_review": False, "is_mitigated": False, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0"}
FINDING_13 = {"id": 245, "date": date(2017, 12, 27), "severity": "Low", "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 22, "out_of_scope": False, "risk_accepted": False, "under_review": False, "is_mitigated": False, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0"}
FINDING_14 = {"id": 246, "date": date(2018, 1, 2), "severity": "Low", "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 22, "out_of_scope": False, "risk_accepted": False, "under_review": False, "is_mitigated": False, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0"}
FINDING_15 = {"id": 247, "date": date(2018, 1, 3), "severity": "Low", "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": None, "out_of_scope": False, "risk_accepted": False, "under_review": False, "is_mitigated": False, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0"}
FINDING_16 = {"id": 248, "date": date(2017, 12, 27), "severity": "Low", "active": True, "verified": True, "false_p": False, "duplicate": False, "duplicate_finding_id": None, "out_of_scope": False, "risk_accepted": False, "under_review": False, "is_mitigated": True, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0"}
FINDING_17 = {"id": 249, "date": date(2018, 1, 4), "severity": "Low", "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 224, "out_of_scope": False, "risk_accepted": False, "under_review": False, "is_mitigated": False, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0"}


ALL_FINDINGS = [FINDING_1, FINDING_2, FINDING_3, FINDING_4, FINDING_5, FINDING_6, FINDING_7, FINDING_8, FINDING_9,
                FINDING_10, FINDING_11, FINDING_12, FINDING_13, FINDING_14, FINDING_15, FINDING_16, FINDING_17]
CLOSED_FINDINGS = [FINDING_11, FINDING_16]
ACCEPTED_FINDINGS = [FINDING_9, FINDING_10, FINDING_11]


class FindingQueriesTest(DojoTestCase):
    fixtures = ["dojo_testdata.json", "unit_metrics_additional_data.json"]

    def setUp(self):
        user = User.objects.get(username="user1")
        self.request = RequestFactory().get(reverse("metrics"), {
            "start_date": "2017-12-26",
            "end_date": "2018-01-05",
        })
        self.request.user = user
        self.request._messages = MockMessages()

    def test_finding_queries_no_data(self):
        user3 = User.objects.get(username="user3")
        self.request.user = user3

        product_types = []
        finding_queries = utils.finding_queries(
            product_types,
            self.request,
        )

        self.assertSequenceEqual(
            finding_queries["all"].values(),
            [],
        )

    @patch("django.utils.timezone.now")
    def test_finding_queries(self, mock_timezone):
        self.maxDiff = None
        mock_datetime = datetime(2020, 12, 9, tzinfo=zoneinfo.ZoneInfo("UTC"))
        mock_timezone.return_value = mock_datetime

        # Queries over Finding
        with self.assertNumQueries(28):
            product_types = []
            finding_queries = utils.finding_queries(
                product_types,
                self.request,
            )
            self.assertSequenceEqual(
                list(finding_queries.keys()),
                [
                    "all",
                    "closed",
                    "accepted",
                    "accepted_count",
                    "top_ten",
                    "monthly_counts",
                    "weekly_counts",
                    "weeks_between",
                    "start_date",
                    "end_date",
                    "form",
                ],
            )
            # Assert that we get expected querysets back. This is to be used to
            # support refactoring, in attempt of lowering the query count.
            # we limit ourselves to the most interesting subset of fields otherwise this tests become unmaintainable
            self.assertSequenceEqual(finding_queries["all"].values(*FINDING_1.keys()), ALL_FINDINGS)
            self.assertSequenceEqual(finding_queries["closed"].values(*FINDING_1.keys()), CLOSED_FINDINGS)
            self.assertSequenceEqual(finding_queries["accepted"].values(*FINDING_1.keys()), ACCEPTED_FINDINGS)

            self.assertSequenceEqual(
                finding_queries["accepted_count"],
                {"total": 3, "critical": 0, "high": 3, "medium": 0, "low": 0, "info": 0},
            )
            self.assertSequenceEqual(
                finding_queries["top_ten"].values(),
                [],
            )
            self.assertEqual(
                finding_queries["monthly_counts"],
                {
                    "opened_per_period": [
                        {"epoch": 1509494400000, "grouped_date": date(2017, 11, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0, "closed": 0},
                        {"epoch": 1512086400000, "grouped_date": date(2017, 12, 1), "critical": 0, "high": 2, "medium": 0, "low": 3, "info": 0, "total": 5, "closed": 2},
                        {"epoch": 1514764800000, "grouped_date": date(2018, 1, 1), "critical": 0, "high": 6, "medium": 0, "low": 6, "info": 0, "total": 12, "closed": 0},
                    ],
                    "active_per_period": [
                        {"epoch": 1509494400000, "grouped_date": date(2017, 11, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                        {"epoch": 1512086400000, "grouped_date": date(2017, 12, 1), "critical": 0, "high": 0, "medium": 0, "low": 2, "info": 0, "total": 2},
                        {"epoch": 1514764800000, "grouped_date": date(2018, 1, 1), "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 1},
                    ],
                    "accepted_per_period": [
                        {"epoch": 1509494400000, "grouped_date": date(2017, 11, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                        {"epoch": 1512086400000, "grouped_date": date(2017, 12, 1), "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 1},
                        {"epoch": 1514764800000, "grouped_date": date(2018, 1, 1), "critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0, "total": 2},
                    ],
                },
            )
            self.assertEqual(
                finding_queries["weekly_counts"],
                {
                    "opened_per_period": [
                        {"epoch": 1513555200000, "grouped_date": date(2017, 12, 18), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0, "closed": 0},
                        {"epoch": 1514160000000, "grouped_date": date(2017, 12, 25), "critical": 0, "high": 2, "medium": 0, "low": 3, "info": 0, "total": 5, "closed": 2},
                        {"epoch": 1514764800000, "grouped_date": date(2018, 1, 1), "critical": 0, "high": 6, "medium": 0, "low": 6, "info": 0, "total": 12, "closed": 0},
                    ],
                    "active_per_period": [
                        {"epoch": 1513555200000, "grouped_date": date(2017, 12, 18), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                        {"epoch": 1514160000000, "grouped_date": date(2017, 12, 25), "critical": 0, "high": 0, "medium": 0, "low": 2, "info": 0, "total": 2},
                        {"epoch": 1514764800000, "grouped_date": date(2018, 1, 1), "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 1},
                    ],
                    "accepted_per_period": [
                        {"epoch": 1513555200000, "grouped_date": date(2017, 12, 18), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                        {"epoch": 1514160000000, "grouped_date": date(2017, 12, 25), "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 1},
                        {"epoch": 1514764800000, "grouped_date": date(2018, 1, 1), "critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0, "total": 2},
                    ],
                },
            )
            self.assertEqual(finding_queries["weeks_between"], 2)
            self.assertIsInstance(finding_queries["start_date"], datetime)
            self.assertIsInstance(finding_queries["end_date"], datetime)


class EndpointQueriesTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        user = User.objects.get(username="user1")
        self.request = RequestFactory().get(reverse("metrics"))
        self.request.user = user
        self.request._messages = MockMessages()

    def test_endpoint_queries_no_data(self):
        user3 = User.objects.get(username="user3")
        self.request.user = user3

        product_types = []
        endpoint_queries = utils.endpoint_queries(
            product_types,
            self.request,
        )

        self.assertSequenceEqual(
            endpoint_queries["all"].values(),
            [],
        )

    @patch("dojo.filters.now")
    def test_endpoint_queries(self, mock_now):
        fake_now = datetime(2020, 7, 1, tzinfo=zoneinfo.ZoneInfo("UTC"))
        mock_now.return_value = fake_now

        # Queries over Finding and Endpoint_Status
        with self.assertNumQueries(44):
            product_types = Product_Type.objects.all()
            endpoint_queries = utils.endpoint_queries(
                product_types,
                self.request,
            )

            self.assertSequenceEqual(
                list(endpoint_queries.keys()),
                [
                    "all",
                    "closed",
                    "accepted",
                    "accepted_count",
                    "top_ten",
                    "monthly_counts",
                    "weekly_counts",
                    "weeks_between",
                    "start_date",
                    "end_date",
                    "form",
                ],
            )

            # Assert that we get expected querysets back. This is to be used to
            # support refactoring, in attempt of lowering the query count.

            # https://docs.python.org/3/library/unittest.html#unittest.TestCase.assertCountEqual
            # Test that sequence first contains the same elements as second, regardless of their order. When they don't, an error message listing the differences between the sequences will be generated.
            # Duplicate elements are not ignored when comparing first and second. It verifies whether each element has the same count in both sequences. Equivalent to: assertEqual(Counter(list(first)), Counter(list(second))) but works with sequences of unhashable objects as well.
            self.assertCountEqual(
                endpoint_queries["all"].values(),
                [
                    {"id": 1, "date": date(2020, 7, 1), "last_modified": datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=zoneinfo.ZoneInfo("UTC")), "mitigated": False, "mitigated_time": None, "mitigated_by_id": None, "false_positive": False, "out_of_scope": False, "risk_accepted": False, "endpoint_id": 2, "finding_id": 2, "endpoint__product__prod_type__member": False, "endpoint__product__member": True, "endpoint__product__prod_type__authorized_group": False, "endpoint__product__authorized_group": False},
                    {"id": 3, "date": date(2020, 7, 1), "last_modified": datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=zoneinfo.ZoneInfo("UTC")), "mitigated": False, "mitigated_time": None, "mitigated_by_id": None, "false_positive": True, "out_of_scope": False, "risk_accepted": False, "endpoint_id": 5, "finding_id": 228, "endpoint__product__prod_type__member": True, "endpoint__product__member": True, "endpoint__product__prod_type__authorized_group": False, "endpoint__product__authorized_group": False},
                    {"id": 4, "date": date(2020, 7, 1), "last_modified": datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=zoneinfo.ZoneInfo("UTC")), "mitigated": False, "mitigated_time": None, "mitigated_by_id": None, "false_positive": False, "out_of_scope": True, "risk_accepted": False, "endpoint_id": 5, "finding_id": 229, "endpoint__product__prod_type__member": True, "endpoint__product__member": True, "endpoint__product__prod_type__authorized_group": False, "endpoint__product__authorized_group": False},
                    {"id": 5, "date": date(2020, 7, 1), "last_modified": datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=zoneinfo.ZoneInfo("UTC")), "mitigated": False, "mitigated_time": None, "mitigated_by_id": None, "false_positive": False, "out_of_scope": False, "risk_accepted": True, "endpoint_id": 5, "finding_id": 230, "endpoint__product__prod_type__member": True, "endpoint__product__member": True, "endpoint__product__prod_type__authorized_group": False, "endpoint__product__authorized_group": False},
                    {"id": 7, "date": date(2020, 7, 1), "last_modified": datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=zoneinfo.ZoneInfo("UTC")), "mitigated": False, "mitigated_time": None, "mitigated_by_id": None, "false_positive": False, "out_of_scope": False, "risk_accepted": False, "endpoint_id": 7, "finding_id": 227, "endpoint__product__prod_type__member": True, "endpoint__product__member": True, "endpoint__product__prod_type__authorized_group": False, "endpoint__product__authorized_group": False},
                    {"id": 8, "date": date(2020, 7, 1), "last_modified": datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=zoneinfo.ZoneInfo("UTC")), "mitigated": False, "mitigated_time": None, "mitigated_by_id": None, "false_positive": False, "out_of_scope": False, "risk_accepted": False, "endpoint_id": 8, "finding_id": 231, "endpoint__product__prod_type__member": True, "endpoint__product__member": True, "endpoint__product__prod_type__authorized_group": False, "endpoint__product__authorized_group": False},
                ],
            )
            self.assertSequenceEqual(
                endpoint_queries["closed"].values(),
                [],
            )
            self.assertSequenceEqual(
                endpoint_queries["accepted"].values(),
                [{"id": 5, "date": date(2020, 7, 1), "last_modified": datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=zoneinfo.ZoneInfo("UTC")), "mitigated": False, "mitigated_time": None, "mitigated_by_id": None, "false_positive": False, "out_of_scope": False, "risk_accepted": True, "endpoint_id": 5, "finding_id": 230, "endpoint__product__prod_type__member": True, "endpoint__product__member": True, "endpoint__product__prod_type__authorized_group": False, "endpoint__product__authorized_group": False}],
            )
            self.assertSequenceEqual(
                list(endpoint_queries["accepted_count"].values()),
                [1, 0, 0, 0, 0, 1],
            )
            self.assertSequenceEqual(
                endpoint_queries["top_ten"].values(),
                [],
            )
            self.assertEqual(
                list(endpoint_queries["monthly_counts"].values()),
                [
                    [
                        {"epoch": 1590969600000, "grouped_date": date(2020, 6, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0, "closed": 0},
                        {"epoch": 1593561600000, "grouped_date": date(2020, 7, 1), "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 5, "total": 6, "closed": 0},
                        {"epoch": 1596240000000, "grouped_date": date(2020, 8, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0, "closed": 0},
                    ],
                    [
                        {"epoch": 1590969600000, "grouped_date": date(2020, 6, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                        {"epoch": 1593561600000, "grouped_date": date(2020, 7, 1), "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 4, "total": 5},
                        {"epoch": 1596240000000, "grouped_date": date(2020, 8, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                    ],
                    [
                        {"epoch": 1590969600000, "grouped_date": date(2020, 6, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                        {"epoch": 1593561600000, "grouped_date": date(2020, 7, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1, "total": 1},
                        {"epoch": 1596240000000, "grouped_date": date(2020, 8, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                    ],
                ],
            )
            self.assertEqual(
                list(endpoint_queries["weekly_counts"].values()),
                [
                    [
                        {"epoch": 1592784000000, "grouped_date": date(2020, 6, 22), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0, "closed": 0},
                        {"epoch": 1593388800000, "grouped_date": date(2020, 6, 29), "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 5, "total": 6, "closed": 0},
                        {"epoch": 1593993600000, "grouped_date": date(2020, 7, 6), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0, "closed": 0},
                    ],
                    [
                        {"epoch": 1592784000000, "grouped_date": date(2020, 6, 22), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                        {"epoch": 1593388800000, "grouped_date": date(2020, 6, 29), "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 4, "total": 5},
                        {"epoch": 1593993600000, "grouped_date": date(2020, 7, 6), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                    ],
                    [
                        {"epoch": 1592784000000, "grouped_date": date(2020, 6, 22), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                        {"epoch": 1593388800000, "grouped_date": date(2020, 6, 29), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1, "total": 1},
                        {"epoch": 1593993600000, "grouped_date": date(2020, 7, 6), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                    ],
                ],
            )
            self.assertEqual(endpoint_queries["weeks_between"], 2)
            self.assertEqual(endpoint_queries["start_date"], datetime(2020, 7, 1, 0, 0, tzinfo=zoneinfo.ZoneInfo("UTC")))
            self.assertEqual(endpoint_queries["end_date"], datetime(2020, 7, 1, 0, 0, tzinfo=zoneinfo.ZoneInfo("UTC")))
