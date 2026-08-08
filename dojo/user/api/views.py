import logging

from crum import get_current_user
from django.contrib.auth import get_user_model
from django.urls import reverse
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import DjangoModelPermissions, IsAuthenticated
from rest_framework.response import Response

from dojo.api_v2.views import DojoModelViewSet, PrefetchDojoModelViewSet, schema_with_prefetch
from dojo.authorization import api_permissions as permissions
from dojo.models import UserContactInfo
from dojo.notifications.helper import create_notification
from dojo.user.api.filters import ApiUserContactInfoFilter, ApiUserFilter
from dojo.user.api.serializer import (
    RevokeApiTokenSerializer,
    UserContactInfoSerializer,
    UserProfileSerializer,
    UserSerializer,
)
from dojo.user.authentication import reset_token_for_user
from dojo.user.utils import user_may_delete_account

logger = logging.getLogger(__name__)

User = get_user_model()


# Authorization: configuration
class UsersViewSet(
    DojoModelViewSet,
):
    serializer_class = UserSerializer
    queryset = User.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiUserFilter
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser,)

    def get_queryset(self):
        return User.objects.all().order_by("id")

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if request.user == instance:
            return Response(
                "Users may not delete themselves",
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not user_may_delete_account(request.user, instance):
            msg = "Only superusers are allowed to delete superusers or staff users."
            raise PermissionDenied(msg)
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(
        detail=True,
        methods=["post"],
        url_path="reset_api_token",
        permission_classes=(IsAuthenticated, permissions.IsSuperUserOrGlobalOwner),
        filter_backends=[],
        pagination_class=None,
    )
    def reset_api_token(self, request, pk=None):
        target_user = self.get_object()
        reset_token_for_user(acting_user=request.user, target_user=target_user)
        return Response(status=status.HTTP_204_NO_CONTENT)


# Authorization: superuser
@extend_schema_view(**schema_with_prefetch())
class UserContactInfoViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = UserContactInfoSerializer
    queryset = UserContactInfo.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_class = ApiUserContactInfoFilter
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)

    def get_queryset(self):
        return UserContactInfo.objects.all().order_by("id")


# Authorization: superuser or global owner
class RevokeApiTokenView(GenericAPIView):

    """
    Revoke an API token by its key value.

    Accepts ``{"key": "<token>"}`` and immediately deletes the matching token. Intended for
    incident response, when a token is found leaked and the owning user is not known.
    """

    permission_classes = (IsAuthenticated, permissions.IsSuperUserOrGlobalOwner)
    serializer_class = RevokeApiTokenSerializer
    pagination_class = None
    filter_backends = []

    @extend_schema(
        request=RevokeApiTokenSerializer,
        responses={204: None},
        summary="Revoke an API token by its key value",
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        key = serializer.validated_data["key"]

        token = Token.objects.select_related("user").filter(key=key).first()
        if token is None:
            # Reported so an operator does not believe a mistyped key was revoked. The endpoint
            # is superuser-only, so this is not an oracle available to untrusted callers.
            msg = "No token matching the provided key."
            raise NotFound(msg)

        target_user = token.user
        token.delete()

        # The explicit expiry described the token just deleted; leaving it set would expire the
        # user's next token immediately.
        uci = getattr(target_user, "usercontactinfo", None)
        if uci is not None and uci.token_expiry is not None:
            uci.token_expiry = None
            uci.save(update_fields=["token_expiry"])

        logger.info(
            "API token for user %s revoked by %s",
            target_user.username,
            request.user.username,
        )

        # The owner's automation just stopped working; tell them why.
        create_notification(
            event="other",
            title="API Token Revoked",
            description=(
                f"Your API token has been revoked by "
                f"{request.user.get_full_name() or request.user.username}. "
                f"Generate a new token via the UI to keep using the API."
            ),
            recipients=[target_user],
            url=reverse("api_v2_key"),
            requested_by=request.user,
            icon="key",
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


# Authorization: authenticated users
class UserProfileView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    pagination_class = None
    serializer_class = UserProfileSerializer

    @action(
        detail=True, methods=["get"], filter_backends=[], pagination_class=None,
    )
    def get(self, request, _=None):
        user = get_current_user()
        user_contact_info = (
            user.usercontactinfo if hasattr(user, "usercontactinfo") else None
        )
        serializer = UserProfileSerializer(
            {
                "user": user,
                "user_contact_info": user_contact_info,
            },
            many=False,
        )
        return Response(serializer.data)
