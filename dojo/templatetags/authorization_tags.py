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


@register.filter
def user_has_view_permission(user, permission):
    return configuration_permission(user, permission.app + '.' + permission.view_component_name())


@register.filter
def user_has_add_permission(user, permission):
    return configuration_permission(user, permission.app + '.' + permission.add_component_name())


@register.filter
def user_has_change_permission(user, permission):
    return configuration_permission(user, permission.app + '.' + permission.change_component_name())


@register.filter
def user_has_delete_permission(user, permission):
    return configuration_permission(user, permission.app + '.' + permission.delete_component_name())
