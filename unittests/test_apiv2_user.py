from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

from dojo.models import Global_Role, Role, User, UserContactInfo
from unittests.dojo_test_case import versioned_fixtures


@versioned_fixtures
class UserTest(APITestCase):

    """Test the User APIv2 endpoint."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

    def test_user_list(self):
        r = self.client.get(reverse("user-list"))
        self.assertEqual(r.status_code, 200, r.content[:1000])
        user_list = r.json()["results"]
        self.assertGreaterEqual(len(user_list), 1, r.content[:1000])
        for user in user_list:
            for item in ["username", "first_name", "last_name", "email"]:
                self.assertIn(item, user, r.content[:1000])
            for item in ["password"]:
                self.assertNotIn(item, user, r.content[:1000])

    def test_user_add(self):
        # user with good password
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-2",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])

        # test password by fetching API key
        r = self.client.post(reverse("api-token-auth"), {
            "username": "api-user-2",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])

        # user with weak password
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-3",
            "email": "admin@dojo.com",
            "password": "weakPassword",
        }, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn("Password must contain at least 1 digit, 0-9.", r.content.decode("utf-8"))

    def test_user_change_password(self):
        # some user
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-4",
            "email": "admin@dojo.com",
            "password": "testTEST1234!@#$",
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        user_id = r.json()["id"]

        r = self.client.put("{}{}/".format(reverse("user-list"), user_id), {
            "username": "api-user-4",
            "first_name": "first",
            "email": "admin@dojo.com",
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])

        r = self.client.patch("{}{}/".format(reverse("user-list"), user_id), {
            "last_name": "last",
            "email": "admin@dojo.com",
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])

        r = self.client.put("{}{}/".format(reverse("user-list"), user_id), {
            "username": "api-user-4",
            "email": "admin@dojo.com",
            "password": "testTEST1234!@#$",
        }, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn("Update of password though API is not allowed", r.content.decode("utf-8"))

        r = self.client.patch("{}{}/".format(reverse("user-list"), user_id), {
            "password": "testTEST1234!@#$",
            "email": "admin@dojo.com",
        }, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn("Update of password though API is not allowed", r.content.decode("utf-8"))

    def test_user_deactivate(self):
        # user with good password
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-10",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])

        # user with good password
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-2",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        user_id = r.json()["id"]

        # deactivate
        r = self.client.patch("{}{}/".format(reverse("user-list"), user_id), {
            "is_active": False,
        }, format="json")
        self.assertEqual(r.status_code, 200, r.content[:1000])

        # check is_active field
        r = self.client.get("{}{}/".format(reverse("user-list"), user_id))
        self.assertEqual(r.status_code, 200, r.content[:1000])
        self.assertEqual(r.json()["is_active"], False, r.content[:1000])

        # API key retrieval should fail for inactive user
        r = self.client.post(reverse("api-token-auth"), {
            "username": "api-user-2",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 400, r.content[:1000])

    def test_user_reset_api_token_as_superuser(self):
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-reset-1",
            "email": "admin@dojo.com",
            "password": "testTEST1234!@#$",
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        user_id = r.json()["id"]

        target_user = User.objects.get(id=user_id)
        # Tokens aren't created automatically for new users; ensure one exists.
        old_token = Token.objects.get_or_create(user=target_user)[0].key

        url = "{}{}/reset_api_token/".format(reverse("user-list"), user_id)
        r = self.client.post(url)
        self.assertEqual(r.status_code, 204, r.content[:1000])

        new_token = Token.objects.get(user=target_user).key
        self.assertNotEqual(old_token, new_token)

        uci = UserContactInfo.objects.get(user=target_user)
        self.assertIsNotNone(uci.token_last_reset)
        self.assertLess(abs((timezone.now() - uci.token_last_reset).total_seconds()), 30)

    def test_user_reset_api_token_denies_self(self):
        admin_user = User.objects.get(username="admin")
        admin_token_before = Token.objects.get(user=admin_user).key

        url = "{}{}/reset_api_token/".format(reverse("user-list"), admin_user.id)
        r = self.client.post(url)
        self.assertIn(r.status_code, {400, 403}, r.content[:1000])

        admin_token_after = Token.objects.get(user=admin_user).key
        self.assertEqual(admin_token_before, admin_token_after)

    def test_user_reset_api_token_denies_non_privileged(self):
        # Create a target
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-reset-target",
            "email": "admin@dojo.com",
            "password": "testTEST1234!@#$",
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        target_id = r.json()["id"]

        # Create a non-privileged user and authenticate as them
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-nonpriv",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])

        token_resp = self.client.post(reverse("api-token-auth"), {
            "username": "api-user-nonpriv",
            "password": password,
        }, format="json")
        self.assertEqual(token_resp.status_code, 200, token_resp.content[:1000])
        nonpriv_token = token_resp.json()["token"]

        nonpriv_client = APIClient()
        nonpriv_client.credentials(HTTP_AUTHORIZATION="Token " + nonpriv_token)

        url = "{}{}/reset_api_token/".format(reverse("user-list"), target_id)
        r = nonpriv_client.post(url)
        self.assertEqual(r.status_code, 403, r.content[:1000])

    def test_user_reset_api_token_allows_global_owner(self):
        # Create a global-owner user (not superuser)
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-global-owner",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        global_owner = User.objects.get(username="api-user-global-owner")

        owner_role, _ = Role.objects.get_or_create(name="Owner", defaults={"is_owner": True})
        if not owner_role.is_owner:
            owner_role.is_owner = True
            owner_role.save(update_fields=["is_owner"])
        Global_Role.objects.update_or_create(user=global_owner, defaults={"role": owner_role})

        # Create target
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-reset-2",
            "email": "admin@dojo.com",
            "password": "testTEST1234!@#$",
        }, format="json")
        self.assertEqual(r.status_code, 201, r.content[:1000])
        target_id = r.json()["id"]

        # Authenticate as global owner
        token_resp = self.client.post(reverse("api-token-auth"), {
            "username": "api-user-global-owner",
            "password": password,
        }, format="json")
        self.assertEqual(token_resp.status_code, 200, token_resp.content[:1000])
        go_token = token_resp.json()["token"]

        go_client = APIClient()
        go_client.credentials(HTTP_AUTHORIZATION="Token " + go_token)

        url = "{}{}/reset_api_token/".format(reverse("user-list"), target_id)
        r = go_client.post(url)
        self.assertEqual(r.status_code, 204, r.content[:1000])
