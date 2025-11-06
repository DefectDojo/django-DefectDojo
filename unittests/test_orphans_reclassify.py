from .dojo_test_case import DojoTestCase
from dojo.models import Dojo_User, Product, Product_Type, System_Settings
from dojo.engine_tools.views import orphans_reclassification

from django.urls import reverse


class OrphansReclassificationViewTests(DojoTestCase):
    def setUp(self):

        self.user = Dojo_User.objects.create_superuser(
            username='testuser', password='testpass'
        )
        
        self.test_systems_settings = System_Settings.objects.get_or_create()[0]
        self.test_systems_settings.orphan_findings = "EVC - SIN DEFINIR"
        self.test_systems_settings.save()

        self.client.login(username='testuser', password='testpass')

        self.orphan_type = Product_Type.objects.create(name="EVC - SIN DEFINIR")
        self.normal_type = Product_Type.objects.create(name="Normal Product")

        self.product1 = Product.objects.create(
            name="Orphan Product A",
            prod_type=self.orphan_type
        )
        self.product2 = Product.objects.create(
            name="Orphan Product B",
            prod_type=self.orphan_type
        )

        self.product3 = Product.objects.create(
            name="Regular Product",
            prod_type=self.normal_type
        )

        self.url = reverse("orphans_reclassification")

    def test_view_renders_successfully(self):
        response = self.client.get(self.url)
        assert response.status_code == 200

        orphan_products = response.context['orphan_products']
        assert self.product1 in orphan_products
        assert self.product2 in orphan_products

        assert self.product3 not in orphan_products

    def test_search_filters_orphan_products(self):
        response = self.client.get(self.url, {'search': 'Product A'})
        assert response.status_code == 200
        orphan_products = response.context['orphan_products']

        assert self.product1 in orphan_products
        assert self.product2 not in orphan_products

