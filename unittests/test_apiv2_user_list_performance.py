from django.contrib.auth.models import Permission
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

from dojo.models import Dojo_User, UserContactInfo
from dojo.user.utils import get_configuration_permissions_codenames
from unittests.dojo_test_case import versioned_fixtures


@versioned_fixtures
class UserListQueryCountTest(APITestCase):

    """
    Regression test for an N+1 on ``GET /api/v2/users/`` (view ``dojo_user-list``).

    ``UserSerializer`` resolves ``usercontactinfo`` (token/password last-reset),
    the auth token (token expiry) and ``user_permissions`` (configuration
    permissions) per row, and ``to_representation`` re-ran a ``values_list`` for
    the allowed configuration permissions once per row. With no ``select_related``
    / ``prefetch_related`` on the viewset queryset this made the query count grow
    linearly with the number of users returned, so listing a page of ~75 users
    produced 300+ queries in production.

    The list serialization must issue a constant number of queries regardless of
    how many users are returned.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

    def _create_users(self, count, prefix):
        perms = list(
            Permission.objects.filter(
                codename__in=get_configuration_permissions_codenames(),
            )[:2],
        )
        for i in range(count):
            user = Dojo_User.objects.create(
                username=f"{prefix}_{i}",
                email=f"{prefix}_{i}@example.com",
            )
            UserContactInfo.objects.create(user=user)
            Token.objects.create(user=user)
            if perms:
                user.user_permissions.add(*perms)

    def test_user_list_query_count_is_constant(self):
        url = reverse("user-list")

        # Warm up content-type / permission caches so they don't skew the first
        # measured request relative to the second.
        self.client.get(url, {"limit": 1000})

        self._create_users(8, "nplus1_batch_a")
        with CaptureQueriesContext(connection) as ctx_a:
            response_a = self.client.get(url, {"limit": 1000})
        self.assertEqual(response_a.status_code, 200, response_a.content[:1000])
        queries_a = len(ctx_a)

        self._create_users(8, "nplus1_batch_b")
        with CaptureQueriesContext(connection) as ctx_b:
            response_b = self.client.get(url, {"limit": 1000})
        self.assertEqual(response_b.status_code, 200, response_b.content[:1000])
        queries_b = len(ctx_b)

        # Sanity: the second response really does serialize the extra 8 users.
        self.assertEqual(
            response_b.json()["count"],
            response_a.json()["count"] + 8,
        )

        self.assertEqual(
            queries_a,
            queries_b,
            f"GET {url} query count grows with the number of users (N+1): "
            f"{queries_a} queries for {response_a.json()['count']} users vs "
            f"{queries_b} queries for {response_b.json()['count']} users.",
        )

    def test_user_list_still_serializes_related_fields(self):
        """The prefetch/select_related change must not alter serialized output."""
        url = reverse("user-list")
        self._create_users(1, "nplus1_related")
        response = self.client.get(url, {"limit": 1000})
        self.assertEqual(response.status_code, 200, response.content[:1000])
        by_username = {u["username"]: u for u in response.json()["results"]}
        created = by_username["nplus1_related_0"]
        for field in (
            "token_last_reset",
            "token_expiry",
            "password_last_reset",
            "configuration_permissions",
        ):
            self.assertIn(field, created, created)
