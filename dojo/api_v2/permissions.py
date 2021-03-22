from dojo.models import Product_Type, Product
from django.shortcuts import get_object_or_404
from rest_framework import permissions
from dojo.authorization.authorization import user_has_permission
from dojo.authorization.roles_permissions import Permissions


class UserHasEngagementPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'POST':
            product = get_object_or_404(Product, pk=request.data.get('product'))
            return user_has_permission(request.user, product, Permissions.Engagement_Add)
        else:
            return True

    def has_object_permission(self, request, view, obj):
        if request.method == 'GET':
            return user_has_permission(request.user, obj, Permissions.Engagement_View)
        elif request.method == 'PUT' or request.method == 'PATCH':
            return user_has_permission(request.user, obj, Permissions.Engagement_Edit)
        elif request.method == 'DELETE':
            return user_has_permission(request.user, obj, Permissions.Engagement_Delete)
        else:
            return False


class UserHasProductPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'POST':
            product_type = get_object_or_404(Product_Type, pk=request.data.get('prod_type'))
            return user_has_permission(request.user, product_type, Permissions.Product_Type_Add_Product)
        else:
            return True

    def has_object_permission(self, request, view, obj):
        if request.method == 'GET':
            return user_has_permission(request.user, obj, Permissions.Product_View)
        elif request.method == 'PUT' or request.method == 'PATCH':
            return user_has_permission(request.user, obj, Permissions.Product_Edit)
        elif request.method == 'DELETE':
            return user_has_permission(request.user, obj, Permissions.Product_Delete)
        else:
            return False


class UserHasProductTypePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'POST':
            return request.user.is_staff
        else:
            return True

    def has_object_permission(self, request, view, obj):
        if request.method == 'GET':
            return user_has_permission(request.user, obj, Permissions.Product_Type_View)
        elif request.method == 'PUT' or request.method == 'PATCH':
            return user_has_permission(request.user, obj, Permissions.Product_Type_Edit)
        elif request.method == 'DELETE':
            return user_has_permission(request.user, obj, Permissions.Product_Type_Delete)
        else:
            return False


class UserHasTestPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'POST':
            engagement = get_object_or_404(Product, pk=request.data.get('engagement'))
            return user_has_permission(request.user, engagement, Permissions.Test_Add)
        else:
            return True

    def has_object_permission(self, request, view, obj):
        if request.method == 'GET':
            return user_has_permission(request.user, obj, Permissions.Test_View)
        elif request.method == 'PUT' or request.method == 'PATCH':
            return user_has_permission(request.user, obj, Permissions.Test_Edit)
        elif request.method == 'DELETE':
            return user_has_permission(request.user, obj, Permissions.Test_Delete)
        else:
            return False


class IsSuperUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_superuser
