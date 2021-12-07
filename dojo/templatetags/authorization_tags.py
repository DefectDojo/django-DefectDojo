from django import template
from django.conf import settings
from crum import get_current_user
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.authorization import user_has_permission

register = template.Library()


@register.filter
def has_object_permission(obj, permission):

    if settings.FEATURE_AUTHORIZATION_V2:
        return user_has_permission(get_current_user(), obj, Permissions[permission])
    else:
        return False
