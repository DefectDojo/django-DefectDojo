"""
Concurrency test for the scheduled risk acceptance expiry against a write adding findings to it.

The expiry reads an acceptance's members, reactivates them, and stamps the acceptance expired. A
write adding findings to the same acceptance in another transaction is invisible to that read
until it commits, so unless the expiry locks the acceptance before it reads, a finding added at
that moment is stamped into an expired acceptance while it stays risk accepted and inactive.
Nothing visits it again: the daily job only looks at acceptances whose expiry is not handled.

These tests commit real rows on two real database connections, which a ``TestCase`` cannot do
(see unittests/test_dedupe_delete_commit_race.py for the pattern and why). The interleaving is
forced: the adding transaction commits only once the expiry is blocked on a lock it holds, or
has finished.
"""

import threading
import uuid
from datetime import timedelta

from django.db import transaction
from django.test import SimpleTestCase
from django.utils import timezone

import dojo.risk_acceptance.helper as ra_helper
from dojo.models import Engagement, Finding, Product, Product_Type, Risk_Acceptance, Test, Test_Type, User
from unittests.test_dedupe_delete_commit_race import (
    WAIT_TIMEOUT_SECONDS,
    _backend_pid,
    _ConcurrentThread,
    _delete_rows_added_since,
    _high_water_marks,
    _is_waiting_on_a_lock,
    _wait_for,
)


# Regression: the scheduled expiry left a finding added concurrently accepted inside the expired acceptance
class ScheduledExpiryAgainstConcurrentAddTest(SimpleTestCase):

    databases = {"default"}

    def setUp(self):
        super().setUp()
        self.addCleanup(_delete_rows_added_since, _high_water_marks())
        suffix = uuid.uuid4().hex[:12]
        now = timezone.now()
        self.user = User.objects.create(username=f"ra_expiry_race_{suffix}")
        product = Product.objects.create(
            name=f"RA Expiry Race Product {suffix}",
            description="Test",
            prod_type=Product_Type.objects.create(name=f"RA Expiry Race PT {suffix}"),
        )
        engagement = Engagement.objects.create(
            name=f"RA Expiry Race Engagement {suffix}", product=product, target_start=now, target_end=now,
        )
        test = Test.objects.create(
            engagement=engagement,
            test_type=Test_Type.objects.create(name=f"RA Expiry Race {suffix}"),
            target_start=now,
            target_end=now,
        )
        # bulk_create keeps Finding.save() side effects (dedupe, grading, hashing) out of committed rows.
        self.member, self.added = Finding.objects.bulk_create([
            Finding(
                test=test, title=title, severity="High", numerical_severity="S1", description="Test",
                mitigation="Test", impact="Test", reporter=self.user, verified=True,
                active=active, risk_accepted=not active,
            )
            for title, active in ((f"member {suffix}", False), (f"added {suffix}", True))
        ])
        self.risk_acceptance = Risk_Acceptance.objects.create(
            name=f"RA Expiry Race {suffix}",
            owner=self.user,
            reactivate_expired=True,
            expiration_date=now - timedelta(days=1),
        )
        self.risk_acceptance.accepted_findings.add(self.member)
        engagement.risk_acceptance.add(self.risk_acceptance)

    def _add_while_the_expiry_runs(self):
        """
        Add ``self.added`` to the acceptance in one transaction while the scheduled expiry runs in another.

        The add writes first, then waits until the expiry is blocked on a lock the add holds (or has
        finished) before it commits: the order in which the expiry reads members it cannot see yet.
        """
        added_uncommitted = threading.Event()
        expiry_pid = []

        def add():
            with transaction.atomic():
                ra_helper.add_findings_to_risk_acceptance(
                    None, Risk_Acceptance.objects.get(pk=self.risk_acceptance.pk), [Finding.objects.get(pk=self.added.pk)],
                )
                added_uncommitted.set()
                _wait_for(lambda: bool(expiry_pid), "the expiry to start")
                _wait_for(lambda: expiry.done or _is_waiting_on_a_lock(expiry_pid[0]), "the expiry to block or finish")

        def expire():
            expiry_pid.append(_backend_pid())
            try:
                ra_helper.expiration_handler()
            finally:
                expiry.done = True

        adder = _ConcurrentThread(add)
        expiry = _ConcurrentThread(expire)
        expiry.done = False
        adder.start()
        if not added_uncommitted.wait(WAIT_TIMEOUT_SECONDS):
            adder.join_or_fail(self)
            self.fail("the add never wrote")
        expiry.start()
        adder.join_or_fail(self)
        expiry.join_or_fail(self)

    def test_a_finding_added_while_the_expiry_runs_is_reactivated_with_the_rest(self):
        self._add_while_the_expiry_runs()

        risk_acceptance = Risk_Acceptance.objects.get(pk=self.risk_acceptance.pk)
        self.assertIsNotNone(risk_acceptance.expiration_date_handled, "the acceptance is expired")
        self.assertIn(self.added.id, set(risk_acceptance.accepted_findings.values_list("id", flat=True)))
        for finding in Finding.objects.filter(pk__in=[self.member.pk, self.added.pk]).order_by("id"):
            self.assertEqual(
                (finding.active, finding.risk_accepted), (True, False),
                msg=(
                    f"finding {finding.title!r} in the expired acceptance should be reactivated, "
                    f"persisted active={finding.active} risk_accepted={finding.risk_accepted}"
                ),
            )
