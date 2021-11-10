from django import template
from crum import get_current_user
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.authorization import user_has_global_permission, user_has_permission, \
    user_has_configuration_permission as configuration_permission
from dojo.request_cache import cache_for_request

register = template.Library()


@register.filter
def has_object_permission(obj, permission):
    return user_has_permission(get_current_user(), obj, Permissions[permission])


@register.filter
def has_global_permission(permission):
    return user_has_global_permission(get_current_user(), Permissions[permission])


@register.filter
def has_configuration_permission(permission):
    return configuration_permission(get_current_user(), permission)


@cache_for_request
def get_user_permissions(user):
    return user.user_permissions.all()


def user_has_permission_without_group(user, codename):
    permissions = get_user_permissions(user)
    for permission in permissions:
        if permission.codename == codename:
            return True
    return False


@register.filter
def user_has_configuration_permission(user, codename):
    return user_has_permission_without_group(user, codename)


@cache_for_request
def get_group_permissions(group):
    return group.permissions.all()


def group_has_permission(group, codename):
    for permission in get_group_permissions(group):
        if permission.codename == codename:
            return True
    return False


@register.filter
def group_has_configuration_permission(group, codename):
    return group_has_permission(group, codename)
