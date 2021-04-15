from django.core.exceptions import PermissionDenied
from django.conf import settings
from dojo.request_cache import cache_for_request
from dojo.authorization.roles_permissions import Permissions, Roles, get_roles_with_permissions
from dojo.models import Product_Type, Product_Type_Member, Product, Product_Member, Engagement, \
    Test, Finding, Endpoint, Finding_Group


def user_has_permission(user, obj, permission):

    if user.is_superuser:
        return True

    if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
        return True

    if isinstance(obj, Product_Type):
        member = get_product_type_member(user, obj)
        if member is None:
            return False
        return role_has_permission(member.role, permission)
    elif (isinstance(obj, Product) and
            permission.value >= Permissions.Product_View.value):
        # Products inherit permissions of their product type
        if user_has_permission(user, obj.prod_type, permission):
            return True

        # Maybe the user has a role for the product with the requested permissions
        member = get_product_member(user, obj)
        if member is None:
            return False
        return role_has_permission(member.role, permission)
    elif isinstance(obj, Engagement) and permission in Permissions.get_engagement_permissions():
        return user_has_permission(user, obj.product, permission)
    elif isinstance(obj, Test) and permission in Permissions.get_test_permissions():
        return user_has_permission(user, obj.engagement.product, permission)
    elif isinstance(obj, Finding) and permission in Permissions.get_finding_permissions():
        return user_has_permission(user, obj.test.engagement.product, permission)
    elif isinstance(obj, Finding_Group) and permission in Permissions.get_finding_group_permissions():
        return user_has_permission(user, obj.test.engagement.product, permission)
    elif isinstance(obj, Endpoint) and permission in Permissions.get_endpoint_permissions():
        return user_has_permission(user, obj.product, permission)
    elif isinstance(obj, Product_Type_Member) and permission in Permissions.get_product_type_member_permissions():
        if permission == Permissions.Product_Type_Member_Delete:
            # Every member is allowed to remove himself
            return obj.user == user or user_has_permission(user, obj.product_type, permission)
        else:
            return user_has_permission(user, obj.product_type, permission)
    elif isinstance(obj, Product_Member) and permission in Permissions.get_product_member_permissions():
        if permission == Permissions.Product_Member_Delete:
            # Every member is allowed to remove himself
            return obj.user == user or user_has_permission(user, obj.product, permission)
        else:
            return user_has_permission(user, obj.product, permission)
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


@cache_for_request
def get_product_member(user, product):
    try:
        return Product_Member.objects.get(user=user, product=product)
    except Product_Member.DoesNotExist:
        return None


@cache_for_request
def get_product_type_member(user, product_type):
    try:
        return Product_Type_Member.objects.get(user=user, product_type=product_type)
    except Product_Type_Member.DoesNotExist:
        return None
