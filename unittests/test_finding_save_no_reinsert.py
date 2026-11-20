"""
Regression: saving a finding whose row was deleted concurrently re-inserted it.

``Finding.save()`` ended in ``Model.save()`` with neither ``force_update`` nor ``update_fields``.
When a concurrent delete removed the row between the request loading the finding and saving it,
Django's UPDATE matched no row and ``Model._save_table`` fell back to an INSERT under the same
primary key. The finding came back from the stale in-memory copy, without the tags, ``found_by``
and notes the delete had cascaded away, and the API answered 200.

An update of a finding that is already saved now forces the UPDATE, so the miss raises Django's
forced-update ``DatabaseError`` instead, and the findings API answers 404 for it.
"""
from django.contrib.auth.models import User
from django.db import DatabaseError, transaction
from django.utils import timezone

from dojo.models import Engagement, Finding, Product, Product_Type, Test, Test_Type
from unittests.dojo_test_case import DojoTestCase


class TestFindingSaveDoesNotReinsert(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.reporter = User.objects.create(username="save-no-reinsert")
        product = Product.objects.create(
            name="Save No Reinsert",
            description="A product for the save tests.",
            prod_type=Product_Type.objects.create(name="Save No Reinsert"),
        )
        engagement = Engagement.objects.create(
            product=product, target_start=timezone.now(), target_end=timezone.now(),
        )
        cls.test = Test.objects.create(
            engagement=engagement,
            test_type=Test_Type.objects.create(name="Save No Reinsert"),
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _new_finding(self):
        finding = Finding(
            test=self.test,
            title="Save Must Not Reinsert",
            severity="High",
            description="A finding saved after its row was deleted.",
            reporter=self.reporter,
        )
        finding.save_no_options()
        return finding

    def test_save_of_a_deleted_finding_raises_instead_of_reinserting(self):
        finding = self._new_finding()
        finding_id = finding.pk
        Finding.objects.filter(pk=finding_id).delete()

        finding.title = "Renamed After The Delete"
        # The savepoint keeps the test's own transaction usable after the forced-update miss.
        with self.assertRaisesMessage(DatabaseError, "Forced update did not affect any rows"), transaction.atomic():
            finding.save_no_options()

        self.assertFalse(
            Finding.objects.filter(pk=finding_id).exists(),
            msg=f"finding {finding_id} was deleted, and its save re-inserted it",
        )

    def test_save_of_a_present_finding_updates_it(self):
        finding = self._new_finding()

        finding.title = "Renamed Again"
        finding.save_no_options()

        persisted = Finding.objects.get(pk=finding.pk)
        self.assertEqual(persisted.title, "Renamed Again", msg=f"persisted title={persisted.title!r}")

    def test_a_caller_may_still_pass_force_update_or_update_fields(self):
        # The importers' save_matched_finding passes force_update=True itself; the default must not collide with it.
        finding = self._new_finding()

        finding.title = "Forced By The Caller"
        finding.save_no_options(force_update=True)
        finding.title = "Only This Field"
        finding.save_no_options(update_fields=["title"])

        self.assertEqual(Finding.objects.get(pk=finding.pk).title, "Only This Field")

    def test_new_finding_is_still_inserted(self):
        finding = self._new_finding()

        self.assertTrue(Finding.objects.filter(pk=finding.pk).exists())
