"""
Regression tests for the prefetch RBAC gate.

The ``?prefetch=`` query parameter on viewsets that inherit
``PrefetchDojoModelViewSet`` used to bypass the authorization of the
related viewset entirely (see security report sub-vectors 4a/4b/4c/4e).
These tests pin the corrected behaviour: a non-superuser making the same
request must not see related objects whose top-level viewset is
superuser-only, while a superuser still receives the same payload as
before.
"""

from django.contrib.auth.models import Permission
from django.contrib.auth.models import User as DjangoUser
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.api_v2.prefetch import authorized_querysets
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Notes,
    Product,
    Product_Member,
    Test,
    Test_Type,
    Tool_Configuration,
    Tool_Product_Settings,
    Tool_Type,
)
from unittests.dojo_test_case import DojoAPITestCase, versioned_fixtures


@versioned_fixtures
class PrefetchRBACTest(DojoAPITestCase):

    """Verify that the prefetch path enforces authorization on related objects."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        # A regular (non-superuser) user with Owner role on product 1 -- the
        # bypass under test would have allowed this account to enumerate
        # users, tool configurations, and notes despite the superuser-only
        # guard on those viewsets.
        self.reader = Dojo_User.objects.get(username="user2")
        self.reader.is_superuser = False
        self.reader.is_staff = False
        self.reader.save()
        self.reader_token, _ = Token.objects.get_or_create(user=self.reader)

        self.admin = Dojo_User.objects.get(username="admin")
        self.admin_token, _ = Token.objects.get_or_create(user=self.admin)

        self.product = Product.objects.get(pk=1)
        # OSS authorization keys off the legacy ``authorized_users`` M2M
        # (Pro replaces this with Product_Member through the auth-filter
        # plugin -- see dojo.authorization.query_registrations).
        self.product.authorized_users.add(self.reader)
        Product_Member.objects.get_or_create(
            product=self.product,
            user=self.reader,
            defaults={"role_id": 4},
        )

        engagement = Engagement.objects.filter(product=self.product).first()
        if engagement is None:
            engagement = Engagement.objects.create(
                product=self.product,
                name="prefetch-rbac-eng",
                target_start="2026-01-01",
                target_end="2026-01-02",
            )

        test_type, _ = Test_Type.objects.get_or_create(name="prefetch-rbac-tt")
        test = Test.objects.filter(engagement=engagement).first()
        if test is None:
            test = Test.objects.create(
                engagement=engagement,
                test_type=test_type,
                target_start="2026-01-01",
                target_end="2026-01-02",
                lead=self.admin,
            )

        self.finding = Finding.objects.filter(test=test).first()
        if self.finding is None:
            self.finding = Finding.objects.create(
                title="prefetch-rbac-finding",
                test=test,
                reporter=self.admin,
                severity="Info",
                numerical_severity="S4",
            )

        # A private note attached to the finding. The leak in sub-vector 4e
        # is most acute for these.
        self.private_note = Notes.objects.create(
            entry="INTERNAL: prefetch-rbac private note",
            author=self.admin,
            private=True,
        )
        self.finding.notes.add(self.private_note)

        # A Tool_Configuration linked to the product through Tool_Product_Settings
        # is the exact shape exploited in sub-vector 4b.
        tool_type, _ = Tool_Type.objects.get_or_create(name="prefetch-rbac-tt")
        self.tool_config = Tool_Configuration.objects.create(
            name="Internal-Tool-prefetch-rbac",
            url="https://internal.example.invalid",
            username="svc-account-prefetch-rbac",
            authentication_type="API",
            api_key="should-not-leak",
            tool_type=tool_type,
        )
        self.tool_product_settings = Tool_Product_Settings.objects.create(
            name="prefetch-rbac-tps",
            product=self.product,
            tool_configuration=self.tool_config,
            url="https://internal.example.invalid",
        )

    # ---- 4a: user enumeration via Finding.reporter -----------------------

    def _client(self, token):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        return client

    def test_admin_can_prefetch_reporter(self):
        """Superuser baseline -- prefetched reporter is still returned."""
        resp = self._client(self.admin_token).get(
            f"/api/v2/findings/{self.finding.pk}/?prefetch=reporter",
        )
        self.assertEqual(200, resp.status_code, resp.content[:500])
        prefetch = resp.json().get("prefetch", {})
        self.assertIn("reporter", prefetch)
        self.assertIn(str(self.admin.pk), prefetch["reporter"])

    def test_reader_cannot_prefetch_reporter(self):
        """Sub-vector 4a -- a non-superuser must not receive user data via prefetch."""
        resp = self._client(self.reader_token).get(
            f"/api/v2/findings/{self.finding.pk}/?prefetch=reporter",
        )
        self.assertEqual(200, resp.status_code, resp.content[:500])
        prefetch = resp.json().get("prefetch", {})
        # Either the key is absent or it is present but empty -- in both
        # cases no user data has been disclosed.
        self.assertFalse(prefetch.get("reporter"))

    def test_user_with_view_perm_can_prefetch_reporter(self):
        """
        ``django_view_perm`` lets a non-superuser with an explicit
        ``dojo.view_dojo_user`` grant prefetch reporter -- matching what
        ``UsersViewSet`` (gated by DjangoModelPermissions) already allows
        them to do via the top-level endpoint.
        """
        view_user = Permission.objects.get(
            content_type__app_label="dojo",
            codename="view_dojo_user",
        )
        self.reader.user_permissions.add(view_user)
        # has_perm caches per instance -- reload to pick up the new perm.
        self.reader = Dojo_User.objects.get(pk=self.reader.pk)
        self.reader_token, _ = Token.objects.get_or_create(user=self.reader)

        resp = self._client(self.reader_token).get(
            f"/api/v2/findings/{self.finding.pk}/?prefetch=reporter",
        )
        self.assertEqual(200, resp.status_code, resp.content[:500])
        prefetch = resp.json().get("prefetch", {})
        self.assertIn("reporter", prefetch)
        self.assertIn(str(self.admin.pk), prefetch["reporter"])

    # ---- 4b: tool configuration disclosure -------------------------------

    def test_admin_can_prefetch_tool_configuration(self):
        resp = self._client(self.admin_token).get(
            f"/api/v2/tool_product_settings/{self.tool_product_settings.pk}/?prefetch=tool_configuration",
        )
        self.assertEqual(200, resp.status_code, resp.content[:500])
        prefetch = resp.json().get("prefetch", {})
        self.assertIn("tool_configuration", prefetch)
        self.assertIn(str(self.tool_config.pk), prefetch["tool_configuration"])

    def test_reader_cannot_prefetch_tool_configuration(self):
        """
        Sub-vector 4b -- prefetching tool_configuration must not leak the
        URL, service-account username, or extras field to a non-superuser.
        """
        resp = self._client(self.reader_token).get(
            f"/api/v2/tool_product_settings/{self.tool_product_settings.pk}/?prefetch=tool_configuration",
        )
        self.assertEqual(200, resp.status_code, resp.content[:500])
        prefetch = resp.json().get("prefetch", {})
        leaked = prefetch.get("tool_configuration", {})
        self.assertFalse(
            leaked,
            f"tool_configuration disclosed via prefetch to non-superuser: {leaked!r}",
        )

    # ---- 4e: private notes disclosure ------------------------------------

    def test_admin_can_prefetch_notes(self):
        resp = self._client(self.admin_token).get(
            f"/api/v2/findings/{self.finding.pk}/?prefetch=notes",
        )
        self.assertEqual(200, resp.status_code, resp.content[:500])
        prefetch = resp.json().get("prefetch", {})
        self.assertIn("notes", prefetch)
        self.assertIn(str(self.private_note.pk), prefetch["notes"])

    def test_reader_cannot_prefetch_private_note_from_other_author(self):
        """
        Sub-vector 4e -- a private note written by someone else must not be
        returned to a non-superuser via prefetch (matches the existing UI
        behaviour where ``notes.filter(private=False)`` hides them).
        """
        resp = self._client(self.reader_token).get(
            f"/api/v2/findings/{self.finding.pk}/?prefetch=notes",
        )
        self.assertEqual(200, resp.status_code, resp.content[:500])
        prefetch = resp.json().get("prefetch", {})
        leaked = prefetch.get("notes", {})
        self.assertNotIn(str(self.private_note.pk), leaked)
        for note in leaked.values():
            self.assertNotIn(
                "INTERNAL: prefetch-rbac private note",
                note.get("entry", ""),
            )

    def test_reader_can_prefetch_public_notes(self):
        """
        ``notes_policy`` lets a non-superuser see non-private notes on
        findings they have parent-product access to.
        """
        public_note = Notes.objects.create(
            entry="public note visible to readers",
            author=self.admin,
            private=False,
        )
        self.finding.notes.add(public_note)

        resp = self._client(self.reader_token).get(
            f"/api/v2/findings/{self.finding.pk}/?prefetch=notes",
        )
        self.assertEqual(200, resp.status_code, resp.content[:500])
        prefetch = resp.json().get("prefetch", {})
        self.assertIn(str(public_note.pk), prefetch.get("notes", {}))
        # The private note authored by admin must still be hidden.
        self.assertNotIn(str(self.private_note.pk), prefetch.get("notes", {}))

    def test_reader_can_prefetch_own_private_notes(self):
        """
        ``notes_policy`` lets a non-superuser see their own private notes
        even on findings where they're not the author of every note.
        """
        own_private = Notes.objects.create(
            entry="reader's own private note",
            author=self.reader,
            private=True,
        )
        self.finding.notes.add(own_private)

        resp = self._client(self.reader_token).get(
            f"/api/v2/findings/{self.finding.pk}/?prefetch=notes",
        )
        self.assertEqual(200, resp.status_code, resp.content[:500])
        prefetch = resp.json().get("prefetch", {})
        self.assertIn(str(own_private.pk), prefetch.get("notes", {}))
        # admin's private note must still be hidden.
        self.assertNotIn(str(self.private_note.pk), prefetch.get("notes", {}))

    # ---- defense in depth: unregistered models are denied ----------------

    def test_unregistered_model_is_denied_by_default(self):
        """
        An attempt to prefetch a field whose related model has no
        registered policy must return an empty prefetch payload, not the
        unfiltered serialized object.
        """
        # Pretend Dojo_User has no registered policy. The deny-by-default
        # path must kick in and the field must not appear in the response.
        original_dojo_user = authorized_querysets._REGISTRY.pop(Dojo_User, None)
        original_user = authorized_querysets._REGISTRY.pop(DjangoUser, None)
        try:
            resp = self._client(self.admin_token).get(
                f"/api/v2/findings/{self.finding.pk}/?prefetch=reporter",
            )
            self.assertEqual(200, resp.status_code)
            prefetch = resp.json().get("prefetch", {})
            self.assertFalse(prefetch.get("reporter"))
        finally:
            if original_dojo_user is not None:
                authorized_querysets._REGISTRY[Dojo_User] = original_dojo_user
            if original_user is not None:
                authorized_querysets._REGISTRY[DjangoUser] = original_user
