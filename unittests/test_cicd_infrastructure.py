"""
Tests for the CICDInfrastructure model, form, and API.

Migration behaviour is tested separately in
``test_cicd_infrastructure_migration.py``.
"""

from django.core.exceptions import ValidationError
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

    def test_save_rejects_infrastructure_type_change_on_existing(self):
        """
        Model save() guard: infrastructure_type is immutable once an instance exists.
        Engagement CICD FKs are scoped by infrastructure_type via limit_choices_to,
        so flipping the type would leave any referencing engagement pointing at a row
        whose type contradicts the FK's role.
        """
        infra = CICDInfrastructure.objects.create(name="Locked", infrastructure_type="build_server")
        infra.infrastructure_type = "scm_server"
        with self.assertRaises(ValidationError) as ctx:
            infra.save()
        self.assertIn("infrastructure_type", ctx.exception.message_dict)
        # The DB row is untouched.
        self.assertEqual(
            CICDInfrastructure.objects.get(pk=infra.pk).infrastructure_type,
            "build_server",
        )

    def test_save_allows_changing_other_fields_on_existing(self):
        """name/description/url remain editable post-creation."""
        infra = CICDInfrastructure.objects.create(name="Editable", infrastructure_type="build_server")
        infra.name = "Renamed"
        infra.description = "now has a description"
        infra.url = "https://renamed.example.com"
        infra.save()
        infra.refresh_from_db()
        self.assertEqual(infra.name, "Renamed")
        self.assertEqual(infra.description, "now has a description")
        self.assertEqual(infra.url, "https://renamed.example.com")


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
    The /cicd_infrastructure endpoint uses UserHasCICDInfrastructurePermission
    — reads are open to any authenticated user; writes require the configuration
    permission (superuser/staff on OS, full RBAC under Pro).
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

    def test_non_superuser_can_list(self):
        # 'user1' (pk=2 in dojo_testdata.json) is a non-superuser with a token.
        # Reads are open to authenticated users.
        try:
            c = self._client_for("user1")
        except Token.DoesNotExist:
            self.skipTest("user1 token not present in dojo_testdata fixture.")
        r = c.get(reverse("cicd_infrastructure-list"))
        self.assertEqual(r.status_code, 200, r.content[:1000])

    def test_non_superuser_cannot_create(self):
        try:
            c = self._client_for("user1")
        except Token.DoesNotExist:
            self.skipTest("user1 token not present in dojo_testdata fixture.")
        r = c.post(
            reverse("cicd_infrastructure-list"),
            {"name": "NonSuperCreate", "infrastructure_type": "build_server"},
            format="json",
        )
        self.assertEqual(r.status_code, 403, r.content[:1000])
        self.assertFalse(CICDInfrastructure.objects.filter(name="NonSuperCreate").exists())

    def test_patch_silently_ignores_infrastructure_type_change(self):
        """
        Serializer marks infrastructure_type read_only on update, so DRF drops the
        incoming value from validated_data. The PATCH succeeds (200) but the type is
        unchanged — same defense the form provides for the legacy UI.
        """
        existing = CICDInfrastructure.objects.create(
            name="ApiLocked", infrastructure_type="build_server",
        )
        c = self._client_for("admin")
        r = c.patch(
            reverse("cicd_infrastructure-detail", args=[existing.pk]),
            {"infrastructure_type": "scm_server", "description": "still build"},
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.content[:1000])
        existing.refresh_from_db()
        self.assertEqual(existing.infrastructure_type, "build_server")
        self.assertEqual(existing.description, "still build")
