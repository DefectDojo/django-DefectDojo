# Regression: the seeded default SLA Configuration description and the duplicate-name error on
# Product and Product_Type named "Product" whatever the Asset/Organization relabel setting showed.
import importlib
import json
from pathlib import Path

from django.apps import apps
from django.conf import settings
from django.test import SimpleTestCase

from dojo.models import Dojo_User, Product, Product_Type, SLA_Configuration
from dojo.product.ui.forms import ProductForm
from dojo.product_type.ui.forms import Product_TypeForm
from unittests.dojo_test_case import DojoAPITestCase

MIGRATION = "dojo.db_migrations.0315_relabel_neutral_seed_and_unique_name"

# Written out rather than imported, so the test pins the exact strings.
OLD_DESCRIPTION = "The Default SLA Configuration. Products not using an explicit SLA Configuration will use this one."
NEW_DESCRIPTION = "The Default SLA Configuration, used wherever no other SLA Configuration is assigned."
OLD_NO_SLA_DESCRIPTION = "No SLA is enforced for a product which uses this SLA configuration."
NEW_NO_SLA_DESCRIPTION = "No SLA is enforced for anything that uses this SLA configuration."
UNIQUE_NAME_MESSAGE = "An entry with this name already exists."
ENTITY_WORDS = ("product", "asset", "organization")
SEED_FIXTURES = ("sla_configurations.json", "defect_dojo_sample_data.json", "defect_dojo_sample_data_locations.json")


def _assert_relabel_neutral(test, text):
    for word in ENTITY_WORDS:
        test.assertNotIn(word, text.lower(), msg=f"{word!r} in {text!r}")


class TestRelabelNeutralUniqueName(DojoAPITestCase):

    def setUp(self):
        settings.SECURE_SSL_REDIRECT = False
        admin = Dojo_User.objects.create(username="relabel-neutral-admin", is_superuser=True, is_staff=True)
        self.client.force_authenticate(user=admin)
        self.product_type = Product_Type.objects.create(name="Relabel neutral PT")
        Product.objects.create(name="Relabel neutral product", description="d", prod_type=self.product_type)

    def test_duplicate_product_name_via_api(self):
        response = self.client.post(
            "/api/v2/products/",
            {"name": "Relabel neutral product", "description": "d", "prod_type": self.product_type.id},
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json()["name"], [UNIQUE_NAME_MESSAGE])
        self.assertEqual(Product.objects.filter(name="Relabel neutral product").count(), 1)

    def test_duplicate_product_type_name_via_api(self):
        response = self.client.post("/api/v2/product_types/", {"name": "Relabel neutral PT"}, format="json")
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json()["name"], [UNIQUE_NAME_MESSAGE])
        self.assertEqual(Product_Type.objects.filter(name="Relabel neutral PT").count(), 1)

    def test_unique_name_message_is_relabel_neutral(self):
        _assert_relabel_neutral(self, UNIQUE_NAME_MESSAGE)

    def test_duplicate_names_via_forms(self):
        product_form = ProductForm(
            data={"name": "Relabel neutral product", "description": "d", "prod_type": self.product_type.id},
        )
        self.assertFalse(product_form.is_valid())
        self.assertEqual(product_form.errors["name"], [UNIQUE_NAME_MESSAGE])
        product_type_form = Product_TypeForm(data={"name": "Relabel neutral PT"})
        self.assertFalse(product_type_form.is_valid())
        self.assertEqual(product_type_form.errors["name"], [UNIQUE_NAME_MESSAGE])


class TestUniqueNameMessageCatalogs(SimpleTestCase):

    """
    The neutral message replaced Django's own unique error, which Django's catalogs translate.

    Every dojo/locale catalog has to carry it, translated everywhere but in the English source catalog, or a
    German or Japanese user reads English. The .po files are checked directly: unit tests run on a checkout
    mounted over the image, so the .mo files the image build compiles are not there to render from.
    """

    def _entry(self, path):
        for block in path.read_text(encoding="utf-8").split("\n\n"):
            lines = block.strip().splitlines()
            if f'msgid "{UNIQUE_NAME_MESSAGE}"' in lines:
                msgstr = next(line for line in lines if line.startswith("msgstr "))
                return msgstr[len('msgstr "'):-1], any(line.startswith("#,") and "fuzzy" in line for line in lines)
        return None, False

    def test_every_catalog_translates_the_unique_name_message(self):
        locale_dir = next(
            (Path(p) for p in settings.LOCALE_PATHS if str(p).endswith("dojo/locale")),
            Path(settings.LOCALE_PATHS[0]),
        )
        catalogs = sorted(locale_dir.glob("*/LC_MESSAGES/django.po"))
        self.assertGreater(len(catalogs), 1)
        for path in catalogs:
            language = path.parent.parent.name
            with self.subTest(language=language):
                msgstr, fuzzy = self._entry(path)
                self.assertIsNotNone(msgstr, f"{language}: no entry for {UNIQUE_NAME_MESSAGE!r}")
                self.assertFalse(fuzzy, f"{language}: the entry is marked fuzzy")
                if language == "en":
                    self.assertEqual(msgstr, "", "the English source catalog keeps an empty msgstr")
                else:
                    self.assertNotIn(msgstr, ("", UNIQUE_NAME_MESSAGE), f"{language}: not translated")


class TestRelabelNeutralDefaultSLADescription(DojoAPITestCase):

    def test_seed_fixtures_use_the_neutral_description(self):
        fixtures_dir = Path(settings.DOJO_ROOT) / "fixtures"
        for name in SEED_FIXTURES:
            with self.subTest(fixture=name):
                rows = json.loads((fixtures_dir / name).read_text())
                descriptions = [r["fields"]["description"] for r in rows if r["model"] == "dojo.sla_configuration"]
                self.assertIn(NEW_DESCRIPTION, descriptions)
                for description in descriptions:
                    _assert_relabel_neutral(self, description)

    def test_migration_rewrites_only_the_exact_old_default(self):
        old_default = SLA_Configuration.objects.create(name="Old default", description=OLD_DESCRIPTION)
        customised = SLA_Configuration.objects.create(name="Customised", description=OLD_DESCRIPTION + " Edited.")
        own_text = SLA_Configuration.objects.create(name="Own text", description="Products in the EU use this.")
        no_sla = SLA_Configuration.objects.create(name="No SLA", description=OLD_NO_SLA_DESCRIPTION)
        empty = SLA_Configuration.objects.create(name="Empty", description=None)

        importlib.import_module(MIGRATION).rewrite_default_sla_description(apps, None)

        persisted = dict(SLA_Configuration.objects.filter(
            id__in=[old_default.id, customised.id, own_text.id, no_sla.id, empty.id],
        ).values_list("name", "description"))
        self.assertEqual(persisted, {
            "Old default": NEW_DESCRIPTION,
            "Customised": OLD_DESCRIPTION + " Edited.",
            "Own text": "Products in the EU use this.",
            "No SLA": NEW_NO_SLA_DESCRIPTION,
            "Empty": None,
        }, msg=f"persisted={persisted}")

    def test_migration_reverse_restores_the_old_default(self):
        sla = SLA_Configuration.objects.create(name="New default", description=NEW_DESCRIPTION)
        no_sla = SLA_Configuration.objects.create(name="New no SLA", description=NEW_NO_SLA_DESCRIPTION)
        importlib.import_module(MIGRATION).restore_default_sla_description(apps, None)
        self.assertEqual(SLA_Configuration.objects.get(id=sla.id).description, OLD_DESCRIPTION)
        self.assertEqual(SLA_Configuration.objects.get(id=no_sla.id).description, OLD_NO_SLA_DESCRIPTION)
