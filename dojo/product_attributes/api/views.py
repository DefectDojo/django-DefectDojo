from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.permissions import IsAuthenticated

from dojo.api_v2.views import DojoModelViewSet
from dojo.authorization import api_permissions as permissions
from dojo.product_attributes.api.serializer import (
    ProductLifecycleSerializer,
    ProductOriginSerializer,
    ProductPlatformSerializer,
)
from dojo.product_attributes.models import Product_Lifecycle, Product_Origin, Product_Platform


# Authorization: authenticated, configuration
class ProductPlatformViewSet(DojoModelViewSet):
    serializer_class = ProductPlatformSerializer
    queryset = Product_Platform.objects.none()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (IsAuthenticated, permissions.UserHasProductPlatformPermission)

    def get_queryset(self):
        return Product_Platform.objects.all().order_by("display_order", "name")


# Authorization: authenticated, configuration
class ProductLifecycleViewSet(DojoModelViewSet):
    serializer_class = ProductLifecycleSerializer
    queryset = Product_Lifecycle.objects.none()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (IsAuthenticated, permissions.UserHasProductLifecyclePermission)

    def get_queryset(self):
        return Product_Lifecycle.objects.all().order_by("display_order", "name")


# Authorization: authenticated, configuration
class ProductOriginViewSet(DojoModelViewSet):
    serializer_class = ProductOriginSerializer
    queryset = Product_Origin.objects.none()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (IsAuthenticated, permissions.UserHasProductOriginPermission)

    def get_queryset(self):
        return Product_Origin.objects.all().order_by("display_order", "name")
