from django import template
from crum import get_current_user
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.authorization import user_has_global_permission, user_has_permission

register = template.Library()


@register.filter
def has_object_permission(obj, permission):
    return user_has_permission(get_current_user(), obj, Permissions[permission])


@register.filter
def has_global_permission(permission):
    return user_has_global_permission(get_current_user(), Permissions[permission])
