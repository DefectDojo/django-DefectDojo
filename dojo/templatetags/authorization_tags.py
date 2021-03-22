from django import template
from django.conf import settings
from crum import get_current_user
from dojo.authorization.roles_permissions import Roles, Permissions
from dojo.authorization.authorization import user_has_permission

register = template.Library()


@register.simple_tag
def role_as_string(id):
    return Roles(id).name


@register.simple_tag
def feature_authorization_v2():
    return settings.FEATURE_AUTHORIZATION_V2


@register.filter
def feature_authorization_v2_or_user_is_staff(user):
    return settings.FEATURE_AUTHORIZATION_V2 or user.is_staff


@register.filter
def has_object_permission(obj, permission):

    if settings.FEATURE_AUTHORIZATION_V2:
        return user_has_permission(get_current_user(), obj, Permissions[permission])
    else:
        return False


@register.filter
def product_type_name(product_type):
    return product_type.name
