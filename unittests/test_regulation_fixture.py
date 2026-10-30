import json
from pathlib import Path

from django.core.management import call_command
from django.test import TestCase

from dojo.models import Regulation

FIXTURE = Path(__file__).resolve().parent.parent / "dojo" / "fixtures" / "regulation.json"


class TestRegulationFixture(TestCase):

    def setUp(self):
        Regulation.objects.all().delete()
        with FIXTURE.open(encoding="utf-8") as f:
            self.acronyms = [row["fields"]["acronym"] for row in json.load(f)]

    def test_fixture_rows_have_no_pk(self):
        with FIXTURE.open(encoding="utf-8") as f:
            rows = json.load(f)
        self.assertEqual([row for row in rows if "pk" in row], [])

    def test_natural_key_round_trip(self):
        regulation = Regulation.objects.create(
            name="Example Regulation", acronym="EXR", category=Regulation.OTHER_CATEGORY, jurisdiction="Nowhere",
        )
        self.assertEqual(regulation.natural_key(), ("EXR",))
        self.assertEqual(Regulation.objects.get_by_natural_key("EXR"), regulation)

    def test_loading_twice_does_not_duplicate_or_renumber(self):
        call_command("loaddata", "regulation", verbosity=0)
        first = dict(Regulation.objects.values_list("acronym", "pk"))
        self.assertCountEqual(first, self.acronyms)

        call_command("loaddata", "regulation", verbosity=0)
        second = dict(Regulation.objects.values_list("acronym", "pk"))
        self.assertEqual(first, second)

    def test_loading_keeps_user_rows_and_matches_existing_rows_by_acronym(self):
        user_row = Regulation.objects.create(
            name="In-house Policy", acronym="IHP", category=Regulation.CORPORATE_CATEGORY, jurisdiction="Internal",
        )
        existing = Regulation.objects.create(
            name="Payment Card Industry Data Security Standard",
            acronym="PCI DSS",
            category=Regulation.FINANCE_CATEGORY,
            jurisdiction="United States",
        )

        call_command("loaddata", "regulation", verbosity=0)

        self.assertTrue(Regulation.objects.filter(pk=user_row.pk, acronym="IHP").exists())
        self.assertEqual(Regulation.objects.get(acronym="PCI DSS").pk, existing.pk)
        self.assertEqual(Regulation.objects.count(), len(self.acronyms) + 1)
