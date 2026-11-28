import datetime

from django.test import Client
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import Dojo_User, Engagement, Engagement_Presets, Product, Product_Type

from .dojo_test_case import DojoTestCase


class EngagementPresetDeletePermissionTest(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        product = Product.objects.create(
            name="Preset Delete Product", description="x",
            prod_type=Product_Type.objects.create(name="Preset Delete PT"),
        )
        cls.member = Dojo_User.objects.create_user(username="preset_delete_member", is_staff=False)
        cls.staff = Dojo_User.objects.create_user(username="preset_delete_staff", is_staff=True)
        product.authorized_users.add(cls.member)
        cls.preset = Engagement_Presets.objects.create(title="Preset Delete", product=product, scope="x")
        today = datetime.date.today()
        cls.engagement = Engagement.objects.create(
            name="Preset Delete Engagement", product=product, preset=cls.preset,
            target_start=today, target_end=today,
        )
        cls.url = reverse("engagement_presets-detail", args=(cls.preset.id,))
        cls.ui_delete_url = reverse("delete_engagement_presets", args=(product.id, cls.preset.id))
        cls.ui_list_url = reverse("engagement_presets", args=(product.id,))

    def _ui_client(self, user):
        client = Client()
        client.force_login(user)
        return client

    def _client(self, user):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.get_or_create(user=user)[0].key}")
        return client

    def test_member_without_delete_permission_cannot_delete_preset(self):
        self.assertEqual(self._client(self.member).delete(self.url).status_code, 403)
        self.assertTrue(Engagement_Presets.objects.filter(id=self.preset.id).exists())
        self.assertTrue(Engagement.objects.filter(id=self.engagement.id).exists())

    def test_member_can_still_edit_preset(self):
        r = self._client(self.member).patch(self.url, {"title": "Renamed"}, format="json")
        self.assertEqual(r.status_code, 200)

    def test_staff_can_delete_preset(self):
        self.assertEqual(self._client(self.staff).delete(self.url).status_code, 204)
        self.assertFalse(Engagement_Presets.objects.filter(id=self.preset.id).exists())

    def test_member_without_delete_permission_cannot_delete_preset_in_ui(self):
        r = self._ui_client(self.member).post(self.ui_delete_url, {"id": self.preset.id})
        self.assertTemplateUsed(r, "403.html")
        self.assertTrue(Engagement_Presets.objects.filter(id=self.preset.id).exists())

    def test_staff_can_delete_preset_in_ui(self):
        r = self._ui_client(self.staff).post(self.ui_delete_url, {"id": self.preset.id})
        self.assertEqual(r.status_code, 302)
        self.assertFalse(Engagement_Presets.objects.filter(id=self.preset.id).exists())

    def test_preset_list_shows_delete_only_with_delete_permission(self):
        self.assertNotContains(self._ui_client(self.member).get(self.ui_list_url), self.ui_delete_url)
        self.assertContains(self._ui_client(self.staff).get(self.ui_list_url), self.ui_delete_url)
