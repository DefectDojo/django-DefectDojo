"""
Tests for the CICDInfrastructure model, form, and API.

Migration behaviour is tested separately in
``test_cicd_infrastructure_migration.py``.
"""

from django.db import IntegrityError, transaction
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

from dojo.cicd_infrastructure.ui.forms import CICDInfrastructureForm
from dojo.models import CICDInfrastructure
from unittests.dojo_test_case import versioned_fixtures

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class CICDInfrastructureModelTests(APITestCase):

    """Model-level constraints and defaults."""

    def test_unique_together_within_same_type_rejects_duplicate(self):
        CICDInfrastructure.objects.create(name="Jenkins", infrastructure_type="build_server")
        with self.assertRaises(IntegrityError), transaction.atomic():
            CICDInfrastructure.objects.create(name="Jenkins", infrastructure_type="build_server")

    def test_same_name_across_different_types_allowed(self):
        """
        unique_together is (name, infrastructure_type), so the same name across
        different types coexists — supports the 'one Jenkins instance, multiple
        roles' case.
        """
        CICDInfrastructure.objects.create(name="Jenkins", infrastructure_type="build_server")
        CICDInfrastructure.objects.create(name="Jenkins", infrastructure_type="scm_server")
        CICDInfrastructure.objects.create(name="Jenkins", infrastructure_type="orchestration")
        self.assertEqual(CICDInfrastructure.objects.filter(name="Jenkins").count(), 3)

    def test_description_and_url_default_to_empty_string(self):
        """Description and url are non-null with default='' (no None values)."""
        infra = CICDInfrastructure.objects.create(name="Bare", infrastructure_type="build_server")
        self.assertEqual(infra.description, "")
        self.assertEqual(infra.url, "")


# ---------------------------------------------------------------------------
# Form
# ---------------------------------------------------------------------------

class CICDInfrastructureFormTests(APITestCase):

    """Form-level behaviour — specifically the type-locked-on-edit rule."""

    def test_infrastructure_type_editable_on_create(self):
        form = CICDInfrastructureForm()
        self.assertFalse(form.fields["infrastructure_type"].disabled)

    def test_infrastructure_type_disabled_on_edit(self):
        existing = CICDInfrastructure.objects.create(
            name="LockedType", infrastructure_type="build_server",
        )
        form = CICDInfrastructureForm(instance=existing)
        self.assertTrue(form.fields["infrastructure_type"].disabled)

    def test_disabled_field_ignores_posted_value(self):
        """
        Django enforces ``disabled=True`` server-side — POSTed values
        for the type field on edit are silently ignored, so users cannot
        sneak around the UI lock.
        """
        existing = CICDInfrastructure.objects.create(
            name="LockedType2", infrastructure_type="build_server",
        )
        form = CICDInfrastructureForm(
            data={
                "name": "LockedType2",
                "description": "",
                "url": "",
                "infrastructure_type": "orchestration",
            },
            instance=existing,
        )
        self.assertTrue(form.is_valid(), form.errors)
        saved = form.save()
        self.assertEqual(saved.infrastructure_type, "build_server")


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@versioned_fixtures
class CICDInfrastructureAPITests(APITestCase):

    """
    The /cicd_infrastructure endpoint uses UserHasConfigurationPermissionSuperuser
    — superusers can do anything; non-superusers need the explicit Django permission.
    """

    fixtures = ["dojo_testdata.json"]

    def _client_for(self, username):
        token = Token.objects.get(user__username=username)
        c = APIClient()
        c.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        return c

    def test_superuser_can_list(self):
        c = self._client_for("admin")
        r = c.get(reverse("cicd_infrastructure-list"))
        self.assertEqual(r.status_code, 200, r.content[:1000])

    def test_superuser_can_create(self):
        c = self._client_for("admin")
        r = c.post(
            reverse("cicd_infrastructure-list"),
            {"name": "Created via API", "infrastructure_type": "build_server"},
            format="json",
        )
        self.assertEqual(r.status_code, 201, r.content[:1000])
        self.assertTrue(CICDInfrastructure.objects.filter(name="Created via API").exists())

    def test_create_rejects_duplicate_name_same_type(self):
        c = self._client_for("admin")
        CICDInfrastructure.objects.create(name="ApiDupe", infrastructure_type="scm_server")
        r = c.post(
            reverse("cicd_infrastructure-list"),
            {"name": "ApiDupe", "infrastructure_type": "scm_server"},
            format="json",
        )
        # DRF translates the unique_together violation to 400.
        self.assertEqual(r.status_code, 400, r.content[:1000])

    def test_create_allows_same_name_different_type(self):
        c = self._client_for("admin")
        CICDInfrastructure.objects.create(name="Shared", infrastructure_type="build_server")
        r = c.post(
            reverse("cicd_infrastructure-list"),
            {"name": "Shared", "infrastructure_type": "orchestration"},
            format="json",
        )
        self.assertEqual(r.status_code, 201, r.content[:1000])

    def test_non_superuser_is_rejected(self):
        # 'user1' (pk=2 in dojo_testdata.json) is a non-superuser with a token.
        try:
            c = self._client_for("user1")
        except Token.DoesNotExist:
            self.skipTest("user1 token not present in dojo_testdata fixture.")
        r = c.get(reverse("cicd_infrastructure-list"))
        self.assertIn(r.status_code, (401, 403), f"expected 401/403, got {r.status_code}")
