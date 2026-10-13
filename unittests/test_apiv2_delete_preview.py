from django.contrib.auth.models import Permission
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import Finding, Notes, Regulation, User
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class DeletePreviewPermissionTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.author = User.objects.create(username="delete-preview-author")
        note = Notes.objects.create(entry="delete preview note", author=self.author)
        Finding.objects.get(id=2).notes.add(note)

        self.viewer = User.objects.create(username="delete-preview-viewer")
        self.viewer.user_permissions.add(Permission.objects.get(content_type__app_label="auth", codename="view_user"))
        self.viewer = User.objects.get(pk=self.viewer.pk)

    def _client(self, user):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + Token.objects.get_or_create(user=user)[0].key)
        return client

    def test_view_permission_allows_detail_but_not_delete_preview(self):
        client = self._client(self.viewer)
        response = client.get(reverse("user-detail", args=(self.author.id,)))
        self.assertEqual(200, response.status_code, response.content[:500])

        response = client.get(reverse("user-delete-preview", args=(self.author.id,)))
        self.assertEqual(403, response.status_code, response.content[:500])
        self.assertNotIn(b"delete preview note", response.content)

    def test_delete_permission_allows_delete_preview(self):
        self.viewer.user_permissions.add(Permission.objects.get(content_type__app_label="auth", codename="delete_user"))
        self.viewer = User.objects.get(pk=self.viewer.pk)
        response = self._client(self.viewer).get(reverse("user-delete-preview", args=(self.author.id,)))
        self.assertEqual(200, response.status_code, response.content[:500])

    def test_superuser_delete_preview(self):
        admin = User.objects.get(username="admin")
        response = self._client(admin).get(reverse("user-delete-preview", args=(self.author.id,)))
        self.assertEqual(200, response.status_code, response.content[:500])
        self.assertIn("Notes", [row["model"] for row in response.json()["results"]])


@versioned_fixtures
class DeletePreviewConfigurationPermissionTest(DojoTestCase):

    """Configuration viewsets guarded by BaseDjangoModelPermission hold delete_preview to the delete permission."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.regulation = Regulation.objects.create(name="Delete preview regulation", acronym="DPR", category="privacy", jurisdiction="EU")
        self.user = User.objects.create(username="delete-preview-regulation-user")

    def _client(self, codenames):
        self.user.user_permissions.set(Permission.objects.filter(content_type__app_label="dojo", codename__in=codenames))
        user = User.objects.get(pk=self.user.pk)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + Token.objects.get_or_create(user=user)[0].key)
        return client

    def test_view_permission_allows_detail_but_not_delete_preview(self):
        client = self._client(["view_regulation"])
        self.assertEqual(200, client.get(reverse("regulations-detail", args=(self.regulation.id,))).status_code)
        self.assertEqual(403, client.get(reverse("regulations-delete-preview", args=(self.regulation.id,))).status_code)

    def test_delete_permission_allows_delete_preview(self):
        client = self._client(["view_regulation", "delete_regulation"])
        self.assertEqual(200, client.get(reverse("regulations-delete-preview", args=(self.regulation.id,))).status_code)
