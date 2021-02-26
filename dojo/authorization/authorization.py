from django.core.exceptions import PermissionDenied
from dojo.authorization.roles_permissions import Permissions, Roles, get_roles_with_permissions
from dojo.models import Product_Type, Product_Type_Member, Product, Product_Member, Engagement, \
    Test, Finding, Endpoint


def user_has_permission(user, obj, permission):

    if user.is_superuser:
        return True

    if isinstance(obj, Product_Type):
        try:
            member = Product_Type_Member.objects.get(user=user, product_type=obj)
        except Product_Type_Member.DoesNotExist:
            return False
        return role_has_permission(member.role, permission)
    elif (isinstance(obj, Product) and
            permission.value >= Permissions.Product_View.value):
        # Products inherit permissions of their product type
        if user_has_permission(user, obj.prod_type, permission):
            return True

        # Maybe the user has a role for the product with the requested permissions
        try:
            member = Product_Member.objects.get(user=user, product=obj)
        except Product_Member.DoesNotExist:
            return False
        return role_has_permission(member.role, permission)
    elif isinstance(obj, Engagement) and permission in Permissions.get_engagement_permissions():
        return user_has_permission(user, obj.product, permission)
    elif isinstance(obj, Test) and permission in Permissions.get_test_permissions():
        return user_has_permission(user, obj.engagement.product, permission)
    elif isinstance(obj, Finding) and permission in Permissions.get_finding_permissions():
        return user_has_permission(user, obj.test.engagement.product, permission)
    elif isinstance(obj, Endpoint) and permission in Permissions.get_endpoint_permissions():
        return user_has_permission(user, obj.product, permission)
    elif isinstance(obj, Product_Type_Member) and permission in Permissions.get_product_type_member_permissions():
        return obj.user == user or user_has_permission(user, obj.product_type, Permissions.Product_Type_Manage_Members)
    elif isinstance(obj, Product_Member) and permission in Permissions.get_product_member_permissions():
        return obj.user == user or user_has_permission(user, obj.product, Permissions.Product_Manage_Members)
    else:
        raise NoAuthorizationImplementedError('No authorization implemented for class {} and permission {}'.
            format(type(obj).__name__, permission))


def user_has_permission_or_403(user, obj, permission):
    if not user_has_permission(user, obj, permission):
        raise PermissionDenied


def get_roles_for_permission(permission):
    if not Permissions.has_value(permission):
        raise PermissionDoesNotExistError('Permission {} does not exist'.format(permission))
    roles_for_permissions = set()
    roles = get_roles_with_permissions()
    for role in roles:
        permissions = roles.get(role)
        if permission in permissions:
            roles_for_permissions.add(role)
    return roles_for_permissions


def role_has_permission(role, permission):
    if not Roles.has_value(role):
        raise RoleDoesNotExistError('Role {} does not exist'.format(role))
    roles = get_roles_with_permissions()
    permissions = roles.get(role)
    return permission in permissions


class NoAuthorizationImplementedError(Exception):
    def __init__(self, message):
        self.message = message


class PermissionDoesNotExistError(Exception):
    def __init__(self, message):
        self.message = message


class RoleDoesNotExistError(Exception):
    def __init__(self, message):
        self.message = message
