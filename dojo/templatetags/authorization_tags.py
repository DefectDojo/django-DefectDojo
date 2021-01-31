from django import template
from django.conf import settings
from crum import get_current_user
from dojo.authorization.roles_permissions import Roles
from dojo.authorization.authorization import user_has_permission

register = template.Library()


@register.simple_tag
def role_as_string(id):
    return Roles(id).name


@register.simple_tag
def feature_new_authorization():
    return settings.FEATURE_NEW_AUTHORIZATION


@register.filter
def feature_new_authorization_or_user_is_staff(user):
    return settings.FEATURE_NEW_AUTHORIZATION or user.is_staff


@register.filter
def has_object_permission(obj, permission):
    if settings.FEATURE_NEW_AUTHORIZATION:
        return user_has_permission(get_current_user(), obj, permission)
    else:
        return get_current_user().is_staff
