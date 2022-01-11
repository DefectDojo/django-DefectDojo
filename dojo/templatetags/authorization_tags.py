from django import template
import crum
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.authorization import user_has_global_permission, user_has_permission, \
    user_has_configuration_permission as configuration_permission
from dojo.request_cache import cache_for_request

register = template.Library()


@register.filter
def has_object_permission(obj, permission):
    return user_has_permission(crum.get_current_user(), obj, Permissions[permission])


@register.filter
def has_global_permission(permission):
    return user_has_global_permission(crum.get_current_user(), Permissions[permission])


@register.filter
def has_configuration_permission(permission, legacy):
    return configuration_permission(crum.get_current_user(), permission, legacy)


@cache_for_request
def get_user_permissions(user):
    return user.user_permissions.all()


@register.filter
def user_has_configuration_permission_without_group(user, codename):
    permissions = get_user_permissions(user)
    for permission in permissions:
        if permission.codename == codename:
            return True
    return False


@cache_for_request
def get_group_permissions(group):
    return group.permissions.all()


@register.filter
def group_has_configuration_permission(group, codename):
    for permission in get_group_permissions(group):
        if permission.codename == codename:
            return True
    return False
