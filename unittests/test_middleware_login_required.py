from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.contrib.auth.models import AnonymousUser
from django.http import HttpResponse
from django.test import RequestFactory
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from dojo.middleware import LoginRequiredMiddleware
from dojo.models import User

from .dojo_test_case import DojoTestCase, versioned_fixtures


class TokenAuthenticatedView(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        return Response({"username": request.user.username})


@versioned_fixtures
class TestLoginRequiredMiddlewareDdUser(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.factory = RequestFactory()
        self.admin = User.objects.get(username="admin")

    def test_sets_dd_user_for_session_authenticated_request(self):
        request = self.factory.get("/dashboard")
        request.user = self.admin

        middleware = LoginRequiredMiddleware(lambda _request: HttpResponse("OK"))
        fake_uwsgi = SimpleNamespace(set_logvar=Mock())

        with patch.dict("sys.modules", {"uwsgi": fake_uwsgi}):
            response = middleware(request)

        self.assertEqual(200, response.status_code)
        fake_uwsgi.set_logvar.assert_called_once_with("dd_user", str(self.admin))

    def test_sets_dd_user_for_drf_token_authenticated_request(self):
        token, _ = Token.objects.get_or_create(user=self.admin)

        request = self.factory.get(
            "/api/v2/mock-endpoint/",
            HTTP_AUTHORIZATION=f"Token {token.key}",
        )
        request.user = AnonymousUser()

        middleware = LoginRequiredMiddleware(TokenAuthenticatedView.as_view())
        fake_uwsgi = SimpleNamespace(set_logvar=Mock())

        with patch.dict("sys.modules", {"uwsgi": fake_uwsgi}):
            response = middleware(request)

        self.assertEqual(200, response.status_code)
        fake_uwsgi.set_logvar.assert_called_once_with("dd_user", str(self.admin))
