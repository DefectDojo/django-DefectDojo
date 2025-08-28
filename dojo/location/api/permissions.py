from rest_framework.permissions import BasePermission

from dojo.api_v2.permissions import check_object_permission, check_post_permission
from dojo.authorization.roles_permissions import Permissions
from dojo.models import (
    Finding,
    Product,
)


class LocationFindingReferencePermission(BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request,
            Finding,
            "finding",
            Permissions.Finding_Edit,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.finding,
            Permissions.Finding_View,
            Permissions.Finding_Edit,
            Permissions.Finding_Edit,
        )


class LocationProductReferencePermission(BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request,
            Product,
            "product",
            Permissions.Product_Edit,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.product,
            Permissions.Product_View,
            Permissions.Product_Edit,
            Permissions.Product_Edit,
        )
