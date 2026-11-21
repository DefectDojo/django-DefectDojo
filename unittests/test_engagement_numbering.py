"""Behavioral coverage for product-local engagement references."""

from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from dojo.models import Dojo_User, Engagement, Product, Product_Type
from dojo.product.numbering import validate_engagement_number_format


class EngagementNumberingTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        product_type = Product_Type.objects.create(name="Numbered product type")
        cls.product = Product.objects.create(
            name="Numbered product",
            description="Test",
            prod_type=product_type,
            engagement_number_format="ENG-{number:04d}",
        )
        cls.other_product = Product.objects.create(
            name="Other numbered product",
            description="Test",
            prod_type=product_type,
            engagement_number_format="OTHER-{number:03d}",
        )
        cls.plain_product = Product.objects.create(name="Plain", description="Test", prod_type=product_type)
        cls.user = Dojo_User.objects.create(username="engagement_number_test", is_staff=True, is_superuser=True)

    def create_engagement(self, product=None):
        today = timezone.now().date()
        return Engagement.objects.create(product=product or self.product, target_start=today, target_end=today)

    def test_numbers_are_local_and_survive_deletion_and_format_changes(self):
        first = self.create_engagement()
        self.assertEqual(first.engagement_number, "ENG-0001")
        self.assertEqual(self.create_engagement(self.other_product).engagement_number, "OTHER-001")
        first.delete()
        self.assertEqual(self.create_engagement().engagement_number, "ENG-0002")
        self.product.engagement_number_format = "NEW-{number}"
        self.product.save()
        self.assertEqual(self.create_engagement().engagement_number, "NEW-3")
        old_number = Engagement.objects.get(product=self.product, engagement_number="ENG-0002").engagement_number
        self.assertEqual(old_number, "ENG-0002")

    def test_copy_and_move_get_a_destination_number(self):
        original = self.create_engagement()
        copied = original.copy()
        self.assertEqual(copied.engagement_number, "ENG-0002")
        original.product = self.other_product
        original.save(update_fields=["product"])
        original.refresh_from_db()
        self.assertEqual(original.engagement_number, "OTHER-001")
        original.product = self.plain_product
        original.save()
        original.refresh_from_db()
        self.assertIsNone(original.engagement_number)

    def test_unnumbered_product_remains_unnumbered(self):
        self.assertIsNone(self.create_engagement(self.plain_product).engagement_number)
        self.plain_product.refresh_from_db()
        self.assertEqual(self.plain_product.engagement_number_counter, 0)

    def test_stale_product_save_cannot_reset_counter(self):
        stale_product = Product.objects.get(pk=self.product.pk)
        self.create_engagement()
        stale_product.description = "Edited while stale"
        stale_product.save()
        self.assertEqual(self.create_engagement().engagement_number, "ENG-0002")

    def test_failed_creation_does_not_consume_a_number(self):
        with self.assertRaises((IntegrityError, ValidationError)):
            Engagement.objects.create(product=self.product)
        self.product.refresh_from_db()
        self.assertEqual(self.product.engagement_number_counter, 0)
        self.assertEqual(self.create_engagement().engagement_number, "ENG-0001")

    def test_invalid_formats_are_rejected(self):
        for value in ("ENG-", "{number}{number}", "{number.__class__}", "{number:99d}", "{number:017d}"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                validate_engagement_number_format(value)
        self.product.engagement_number_format = "{number.__class__}"
        with self.assertRaises(ValidationError):
            self.product.save()

    def test_api_v2_exposes_reference_without_writable_counter(self):
        engagement = self.create_engagement()
        client = APIClient()
        client.force_authenticate(user=self.user)
        engagement_response = client.get(f"/api/v2/engagements/{engagement.pk}/")
        self.assertEqual(engagement_response.status_code, 200)
        self.assertEqual(engagement_response.json()["engagement_number"], "ENG-0001")
        product_response = client.get(f"/api/v2/products/{self.product.pk}/")
        self.assertEqual(product_response.status_code, 200)
        self.assertEqual(product_response.json()["engagement_number_format"], "ENG-{number:04d}")
        self.assertNotIn("engagement_number_counter", product_response.json())
        url = f"/api/v2/engagements/{engagement.pk}/"
        update_response = client.patch(url, {"engagement_number": "FORGED"}, format="json")
        self.assertEqual(update_response.status_code, 200)
        engagement.refresh_from_db()
        self.assertEqual(engagement.engagement_number, "ENG-0001")

    def test_asset_engagement_list_displays_reference(self):
        self.create_engagement()
        client = APIClient()
        client.force_login(self.user)
        response = client.get(f"/asset/{self.product.pk}/engagements")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "ENG-0001")
