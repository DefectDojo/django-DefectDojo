from django import template
from crum import get_current_user
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.authorization import user_has_global_permission, user_has_permission, \
    user_has_configuration_permission as configuration_permission

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


def user_has_permission_without_group(user, codename):
    permissions = user.user_permissions.all()
    for permission in permissions:
        if permission.codename == codename:
            return True
    return False


@register.filter
def user_has_view_permission(user, permission):
    return user_has_permission_without_group(user, permission.view_codename())


@register.filter
def user_has_add_permission(user, permission):
    return user_has_permission_without_group(user, permission.add_codename())


@register.filter
def user_has_change_permission(user, permission):
    return user_has_permission_without_group(user, permission.change_codename())


@register.filter
def user_has_delete_permission(user, permission):
    return user_has_permission_without_group(user, permission.delete_codename())


def group_has_permission(group, codename):
    permissions = group.permissions.all()
    for permission in permissions:
        if permission.codename == codename:
            return True
    return False


@register.filter
def group_has_view_permission(group, permission):
    return group_has_permission(group, permission.view_codename())


@register.filter
def group_has_add_permission(group, permission):
    return group_has_permission(group, permission.add_codename())


@register.filter
def group_has_change_permission(group, permission):
    return group_has_permission(group, permission.change_codename())


@register.filter
def group_has_delete_permission(group, permission):
    return group_has_permission(group, permission.delete_codename())
