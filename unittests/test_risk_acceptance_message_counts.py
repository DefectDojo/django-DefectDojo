"""
The risk acceptance ticket and notification messages count an acceptance's findings without loading them.

Each message used to count the members with ``len(accepted_findings.all())``, which builds every finding as
a whole row. On an acceptance of a million findings, adding one more spent minutes building rows only their
number was read from.
"""

from datetime import timedelta

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

import dojo.risk_acceptance.helper as ra_helper
from dojo.models import Engagement, Finding, Product, Product_Type, Risk_Acceptance, Test, Test_Type, User

# A column only a whole finding row selects: a count or an id read never names it.
WHOLE_ROW = '"dojo_finding"."title"'


# Regression: counting a risk acceptance's findings for a message loaded every one of them as a whole row
class RiskAcceptanceMessageCountTest(TestCase):

    def setUp(self):
        now = timezone.now()
        user = User.objects.create(username="ra_message_counts")
        product = Product.objects.create(
            name="RA Message Counts Product", description="Test",
            prod_type=Product_Type.objects.create(name="RA Message Counts PT"),
        )
        engagement = Engagement.objects.create(
            name="RA Message Counts Engagement", product=product, target_start=now, target_end=now,
        )
        test = Test.objects.create(
            engagement=engagement, test_type=Test_Type.objects.create(name="RA Message Counts"),
            target_start=now, target_end=now,
        )
        findings = [
            Finding.objects.create(test=test, title=f"Finding {n}", severity="High", reporter=user)
            for n in range(3)
        ]
        self.risk_acceptance = Risk_Acceptance.objects.create(
            name="RA Message Counts", owner=user, expiration_date=now + timedelta(days=30),
        )
        self.risk_acceptance.accepted_findings.set(findings)
        engagement.risk_acceptance.add(self.risk_acceptance)

    def test_each_message_counts_the_findings_without_loading_them(self):
        for creator in (
            ra_helper.accepted_message_creator,
            ra_helper.expiration_message_creator,
            ra_helper.expiration_warning_message_creator,
            ra_helper.reinstation_message_creator,
        ):
            with self.subTest(creator=creator.__name__):
                risk_acceptance = Risk_Acceptance.objects.get(id=self.risk_acceptance.id)
                with CaptureQueriesContext(connection) as queries:
                    text = creator(risk_acceptance, 5)
                self.assertIn("with 3 findings", text)
                whole_rows = [
                    query["sql"] for query in queries.captured_queries
                    if WHOLE_ROW in query["sql"].split(" FROM ")[0]
                ]
                self.assertEqual(whole_rows, [], msg="the findings were loaded as whole rows to count them")
