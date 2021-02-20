from rest_framework import permissions
from dojo.authorization.authorization import user_has_permission
from dojo.authorization.roles_permissions import Permissions


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


class IsSuperUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_superuser
