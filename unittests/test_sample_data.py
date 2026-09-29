from django.conf import settings
from django.core.management import call_command

from dojo.models import Product
from dojo.product_attributes.models import Product_Lifecycle, Product_Origin, Product_Platform

from .dojo_test_case import DojoTestCase


class TestSampleData(DojoTestCase):
    def get_fixture_file(self):
        # TODO: Delete this after the move to Locations
        if not settings.V3_FEATURE_LOCATIONS:
            return "dojo/fixtures/defect_dojo_sample_data"
        return "dojo/fixtures/defect_dojo_sample_data_locations"

    def test_loaddata(self):
        """
        The expected command to generate the fixture file is as follows:

        python3 manage.py dumpdata \
            --exclude auth.permission \
            --exclude contenttypes \
            --exclude auditlog.logentry \
            --natural-foreign \
            --natural-primary \
            --indent 2 \
            > /app/dojo/fixtures/defect_dojo_sample_data.json
        """
        try:
            call_command("loaddata", self.get_fixture_file(), verbosity=0)
        except Exception as e:
            self.assertEqual(False, True, e)
        self.assertEqual(True, True)

    # Regression: the sample-data fixtures referenced the Product_Platform / Product_Lifecycle /
    # Product_Origin rows seeded by migration 0297 by pk without shipping the rows themselves, so
    # loading them into a database whose tables had been emptied (``manage.py flush`` on the demo
    # server) failed with "Product_Platform matching query does not exist".
    def test_loaddata_is_self_contained_for_asset_attribute_options(self):
        Product_Platform.objects.all().delete()
        Product_Lifecycle.objects.all().delete()
        Product_Origin.objects.all().delete()

        call_command("loaddata", self.get_fixture_file(), verbosity=0)

        expected = {
            "BodgeIt": ("web", "production", "internal"),
            "Internal CRM App": ("web", "construction", "internal"),
            "Apple Accounting Software": ("web", "production", "purchased"),
        }
        for name, (platform, lifecycle, origin) in expected.items():
            product = Product.objects.get(name=name)
            persisted = (product.platform.value, product.lifecycle.value, product.origin.value)
            self.assertEqual(
                persisted, (platform, lifecycle, origin),
                msg=f"{name}: expected {(platform, lifecycle, origin)}, persisted={persisted}",
            )
