import logging

from crum import get_current_user
from django.contrib.auth import get_user_model
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema_view
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import DjangoModelPermissions, IsAuthenticated
from rest_framework.response import Response

from dojo.api_v2.views import DojoModelViewSet, PrefetchDojoModelViewSet, schema_with_prefetch
from dojo.authorization import api_permissions as permissions
from dojo.models import UserContactInfo
from dojo.user.api.filters import ApiUserContactInfoFilter, ApiUserFilter
from dojo.user.api.serializer import (
    UserContactInfoSerializer,
    UserProfileSerializer,
    UserSerializer,
)
from dojo.user.authentication import reset_token_for_user

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
