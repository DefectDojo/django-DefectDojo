"""User (Dojo_User) CRUD + RBAC + contract tests for API v3 (OS3a)."""
from __future__ import annotations

from django.contrib.auth.models import Permission
from django.db import connection
from django.test.utils import CaptureQueriesContext

from dojo.models import Dojo_User, Product, Product_Type, User

from .base import ApiV3TestCase

_SLIM_KEYS = {"id", "username", "first_name", "last_name", "email", "is_active", "is_superuser", "last_login"}
_PASSWORD = "Zx9!qWtvB2mnLP4k"


class TestApiV3UsersRead(ApiV3TestCase):

    def test_list_envelope_and_slim_shape(self):
        body = self.get_json("users")
        self.assertEqual({"count", "next", "previous", "results"}, set(body) - {"meta"})
        self.assertGreater(body["count"], 0)
        self.assertEqual(_SLIM_KEYS, set(body["results"][0]))

    def test_detail_adds_heavy_fields(self):
        detail = self.get_json(f"users/{self.admin.id}")
        self.assertIn("is_staff", detail)
        self.assertIn("date_joined", detail)
        self.assertEqual("admin", detail["username"])

    def test_detail_unknown_is_404_problem(self):
        response = self.client.get(self.v3_url("users/99999999"))
        self.assertEqual(404, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_fields_projection(self):
        row = self.get_json("users", data={"fields": "id,username"})["results"][0]
        self.assertEqual({"id", "username"}, set(row))


class TestApiV3UsersFilters(ApiV3TestCase):

    def test_filter_username_icontains(self):
        body = self.get_json("users", data={"username__icontains": "admin"})
        self.assertGreater(body["count"], 0)

    def test_filter_is_superuser(self):
        body = self.get_json("users", data={"is_superuser": "true", "limit": 250})
        for row in body["results"]:
            self.assertTrue(row["is_superuser"])

    def test_ordering_by_username(self):
        User.objects.create_user(username="v3_aaa_user", password=_PASSWORD)
        User.objects.create_user(username="v3_zzz_user", password=_PASSWORD)
        names = [r["username"] for r in self.get_json("users", data={"o": "username", "limit": 250})["results"]]
        self.assertEqual(names, sorted(names))

    def test_unknown_filter_param_is_400(self):
        self.get_json("users", data={"not_a_filter": "x"}, expected=400)


class TestApiV3UsersQueryCount(ApiV3TestCase):

    def _query_count(self, params: dict) -> int:
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(self.v3_url("users"), params)
            self.assertEqual(200, response.status_code, response.content[:500])
        return len(ctx.captured_queries)

    def test_query_count_is_independent_of_row_count(self):
        Dojo_User.objects.bulk_create([Dojo_User(username=f"qcount_user_{i}") for i in range(10)])
        first = self._query_count({"limit": 250})
        Dojo_User.objects.bulk_create([Dojo_User(username=f"qcount_user_b{i}") for i in range(90)])
        second = self._query_count({"limit": 250})
        self.assertEqual(first, second, f"query count grew with rows: {first} -> {second}")


class TestApiV3UsersWrite(ApiV3TestCase):

    def test_create_happy_path(self):
        response = self.client.post(
            self.v3_url("users"),
            {"username": "v3_newuser", "email": "v3new@example.com", "first_name": "New",
             "last_name": "User", "password": _PASSWORD},
            format="json",
        )
        self.assertEqual(201, response.status_code, response.content[:500])
        body = response.json()
        self.assertEqual("v3_newuser", body["username"])
        self.assertNotIn("password", body)  # write-only, never echoed
        created = Dojo_User.objects.get(username="v3_newuser")
        self.assertTrue(created.check_password(_PASSWORD))

    def test_create_missing_email_is_400(self):
        response = self.client.post(
            self.v3_url("users"), {"username": "v3_noemail", "password": _PASSWORD}, format="json",
        )
        self.assertEqual(400, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_create_missing_password_is_400_when_required(self):
        # REQUIRE_PASSWORD_ON_USER defaults True -> password is mandatory on create (mirrors v2).
        response = self.client.post(
            self.v3_url("users"), {"username": "v3_nopass", "email": "np@example.com"}, format="json",
        )
        self.assertEqual(400, response.status_code)

    def test_create_unknown_field_is_400(self):
        response = self.client.post(
            self.v3_url("users"),
            {"username": "v3_extra", "email": "e@example.com", "password": _PASSWORD, "bogus": 1},
            format="json",
        )
        self.assertEqual(400, response.status_code)

    def test_create_superuser_as_superuser_ok(self):
        response = self.client.post(
            self.v3_url("users"),
            {"username": "v3_super", "email": "s@example.com", "password": _PASSWORD, "is_superuser": True},
            format="json",
        )
        self.assertEqual(201, response.status_code, response.content[:500])
        self.assertTrue(Dojo_User.objects.get(username="v3_super").is_superuser)

    def test_patch_partial_update(self):
        user = User.objects.create_user(username="v3_patch_user", password=_PASSWORD)
        response = self.client.patch(
            self.v3_url(f"users/{user.id}"), {"first_name": "Patched"}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:500])
        user.refresh_from_db()
        self.assertEqual("Patched", user.first_name)

    def test_patch_password_is_rejected(self):
        user = User.objects.create_user(username="v3_pwuser", password=_PASSWORD)
        response = self.client.patch(
            self.v3_url(f"users/{user.id}"), {"password": _PASSWORD}, format="json",
        )
        self.assertEqual(400, response.status_code)

    def test_delete_other_user(self):
        user = User.objects.create_user(username="v3_del_user", password=_PASSWORD)
        response = self.client.delete(self.v3_url(f"users/{user.id}"))
        self.assertEqual(204, response.status_code)
        self.assertFalse(Dojo_User.objects.filter(pk=user.id).exists())

    def test_delete_self_is_rejected(self):
        response = self.client.delete(self.v3_url(f"users/{self.admin.id}"))
        self.assertEqual(400, response.status_code)
        self.assertTrue(Dojo_User.objects.filter(pk=self.admin.id).exists())


class TestApiV3UsersReplace(ApiV3TestCase):

    """PUT full-replace: reuses the create-shaped UserWrite; password never settable via update."""

    def test_put_full_replace_resets_omitted_optionals(self):
        user = User.objects.create_user(username="v3_put_user", password=_PASSWORD, first_name="Original")
        # PUT without first_name -> resets to its schema default ("").
        response = self.client.put(
            self.v3_url(f"users/{user.id}"),
            {"username": "v3_put_user", "email": "put@example.com"},
            format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:500])
        body = response.json()
        self.assertEqual("put@example.com", body["email"])
        self.assertEqual("", body["first_name"])   # omitted from PUT -> reset to default ("")
        self.assertTrue(body["is_active"])          # default True
        user.refresh_from_db()
        self.assertEqual("", user.first_name)

    def test_put_password_is_rejected(self):
        user = User.objects.create_user(username="v3_put_pw", password=_PASSWORD)
        response = self.client.put(
            self.v3_url(f"users/{user.id}"),
            {"username": "v3_put_pw", "email": "pw@example.com", "password": _PASSWORD},
            format="json",
        )
        self.assertEqual(400, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_put_missing_required_email_is_400(self):
        user = User.objects.create_user(username="v3_put_noemail", password=_PASSWORD)
        response = self.client.put(
            self.v3_url(f"users/{user.id}"), {"username": "v3_put_noemail"}, format="json",
        )
        self.assertEqual(400, response.status_code)

    def test_put_unknown_field_is_400(self):
        user = User.objects.create_user(username="v3_put_extra", password=_PASSWORD)
        response = self.client.put(
            self.v3_url(f"users/{user.id}"),
            {"username": "v3_put_extra", "email": "e@example.com", "bogus": 1},
            format="json",
        )
        self.assertEqual(400, response.status_code)

    def test_put_unauthorized_is_404(self):
        # A plain user's self-only queryset hides the admin -> 404 before the write gate.
        limited = User.objects.create_user(username="v3_put_u_limited", password=_PASSWORD)
        client = self.token_client(user=limited)
        response = client.put(
            self.v3_url(f"users/{self.admin.id}"),
            {"username": "admin", "email": "a@example.com"}, format="json",
        )
        self.assertEqual(404, response.status_code)

    def test_put_visible_but_not_editable_is_403(self):
        # A plain user can see their own record (404 never fires) but lacks auth.change_user -> 403.
        limited = User.objects.create_user(username="v3_put_u_self", password=_PASSWORD)
        client = self.token_client(user=limited)
        response = client.put(
            self.v3_url(f"users/{limited.id}"),
            {"username": "v3_put_u_self", "email": "self@example.com"}, format="json",
        )
        self.assertEqual(403, response.status_code, response.content[:300])


class TestApiV3UsersRbac(ApiV3TestCase):

    def setUp(self):
        super().setUp()
        self.limited = User.objects.create_user(username="v3_user_limited", password=_PASSWORD)

    # --- plain user (no view_user perm): read is SELF-ONLY, self-read guaranteed ---------------
    def test_plain_user_lists_only_self(self):
        client = self.token_client(user=self.limited)
        body = self.get_json("users", client=client)
        self.assertEqual(1, body["count"])
        self.assertEqual([self.limited.id], [r["id"] for r in body["results"]])

    def test_plain_user_can_always_read_own_record(self):
        client = self.token_client(user=self.limited)
        detail = self.get_json(f"users/{self.limited.id}", client=client)
        self.assertEqual(self.limited.id, detail["id"])

    def test_plain_user_cannot_read_other_record(self):
        client = self.token_client(user=self.limited)
        self.get_json(f"users/{self.admin.id}", client=client, expected=404)

    # --- view_user holder: RBAC-scoped visibility (<= v2's "all users" exposure) ---------------
    def test_view_user_holder_gets_scoped_visibility(self):
        self.limited.user_permissions.add(
            Permission.objects.get(codename="view_user", content_type__app_label="auth", content_type__model="user"),
        )
        client = self.token_client(user=self.limited)
        # The scoped queryset (get_authorized_users) always surfaces superusers, so admin is visible
        # to a view_user holder where a plain user (above) gets 404.
        self.get_json(f"users/{self.admin.id}", client=client)

    # --- superuser: sees all -------------------------------------------------------------------
    def test_superuser_sees_all(self):
        other = User.objects.create_user(username="v3_user_other", password=_PASSWORD)
        ids = [r["id"] for r in self.get_json("users", data={"limit": 250})["results"]]
        self.assertIn(other.id, ids)
        self.assertIn(self.admin.id, ids)

    # --- writes stay admin/superuser-only (unchanged) -----------------------------------------
    def test_non_superuser_cannot_create(self):
        client = self.token_client(user=self.limited)
        response = client.post(
            self.v3_url("users"),
            {"username": "v3_denied", "email": "d@example.com", "password": _PASSWORD},
            format="json",
        )
        self.assertEqual(403, response.status_code, response.content[:300])
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_non_superuser_cannot_delete_other(self):
        other = User.objects.create_user(username="v3_other", password=_PASSWORD)
        client = self.token_client(user=self.limited)
        response = client.delete(self.v3_url(f"users/{other.id}"))
        # Self-only queryset -> `other` is invisible -> 404 (never reaches the delete perm check).
        self.assertEqual(404, response.status_code, response.content[:300])


class TestApiV3UsersIdentityFieldAuthz(ApiV3TestCase):

    """
    Parity with PR #15191: a non-superuser delegate holding the user-management configuration
    permissions (``view_user`` + ``change_user``) may reach the write path for another visible
    account, but must NOT be able to change that account's identity fields (``email``/``username``)
    -- changing another user's email enables account takeover via the password-reset flow. The
    delegate can still edit their OWN identity, and superusers remain unrestricted. The
    ``configuration_permissions`` field itself is intentionally out of the v3 write surface (§12
    OS3a), so only the identity-field half of PR #15191 has a v3 attack surface.
    """

    def setUp(self):
        super().setUp()
        # Non-superuser delegate: holds view_user (so co-member accounts are visible via the RBAC
        # queryset) + change_user (so the update route is reachable), nothing more.
        self.delegate = User.objects.create_user(username="v3_identity_delegate", password=_PASSWORD)
        self.delegate.user_permissions.add(
            Permission.objects.get(codename="view_user", content_type__app_label="auth", content_type__model="user"),
            Permission.objects.get(codename="change_user", content_type__app_label="auth", content_type__model="user"),
        )
        self.target = User.objects.create_user(
            username="v3_identity_target", email="target@example.com", password=_PASSWORD,
        )
        # The view_user-scoped queryset returns co-members of the caller's authorized products
        # (plus superusers) -- make delegate and target co-members of one product so the delegate
        # can both see itself and resolve `target` (otherwise both are 404 before the write gate).
        product_type = Product_Type.objects.create(name="v3_identity_pt")
        product = Product.objects.create(name="v3_identity_prod", description="d", prod_type=product_type)
        product.authorized_users.add(self.delegate.pk, self.target.pk)
        self.delegate_client = self.token_client(user=self.delegate)

    def test_delegate_cannot_change_another_users_email(self):
        response = self.delegate_client.patch(
            self.v3_url(f"users/{self.target.id}"), {"email": "attacker@evil.example"}, format="json",
        )
        self.assertEqual(400, response.status_code, response.content[:500])
        self.assertEqual("application/problem+json", response["Content-Type"])
        self.target.refresh_from_db()
        self.assertEqual("target@example.com", self.target.email)

    def test_delegate_cannot_change_another_users_username(self):
        response = self.delegate_client.patch(
            self.v3_url(f"users/{self.target.id}"), {"username": "hijacked"}, format="json",
        )
        self.assertEqual(400, response.status_code, response.content[:500])
        self.target.refresh_from_db()
        self.assertEqual("v3_identity_target", self.target.username)

    def test_delegate_cannot_change_another_users_email_via_put(self):
        response = self.delegate_client.put(
            self.v3_url(f"users/{self.target.id}"),
            {"username": "v3_identity_target", "email": "attacker@evil.example"}, format="json",
        )
        self.assertEqual(400, response.status_code, response.content[:500])
        self.target.refresh_from_db()
        self.assertEqual("target@example.com", self.target.email)

    def test_delegate_put_unchanged_identity_is_allowed(self):
        # A PUT that re-sends the target's current identity is not a change -> not blocked by the
        # identity guard (it fails/passes on other grounds, but never 400s on identity).
        response = self.delegate_client.put(
            self.v3_url(f"users/{self.target.id}"),
            {"username": "v3_identity_target", "email": "target@example.com"}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:500])
        self.target.refresh_from_db()
        self.assertEqual("target@example.com", self.target.email)

    def test_delegate_can_change_own_email(self):
        response = self.delegate_client.patch(
            self.v3_url(f"users/{self.delegate.id}"), {"email": "mynew@example.com"}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:500])
        self.delegate.refresh_from_db()
        self.assertEqual("mynew@example.com", self.delegate.email)

    def test_superuser_can_change_another_users_email(self):
        # Positive control: the admin (superuser, default client) is unrestricted.
        response = self.client.patch(
            self.v3_url(f"users/{self.target.id}"), {"email": "changed@example.com"}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:500])
        self.target.refresh_from_db()
        self.assertEqual("changed@example.com", self.target.email)
