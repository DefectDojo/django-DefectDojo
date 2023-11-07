from django import template
from django.conf import settings
import crum
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.authorization import user_has_global_permission, user_has_permission, \
    user_has_configuration_permission as configuration_permission
from dojo.models import Finding
from dojo.request_cache import cache_for_request

register = template.Library()



@register.filter
def has_risk_acceptance_permission(finding: Finding):
    result = False
    user = crum.get_current_user()
    rule = settings.RULE_RISK_ACCEPTANCE_ACCORDING_TO_CRITICALITY.get(finding.severity)
    if rule:
        if user.global_role.role.name in rule["roles"]:
            result = True
        return result
    else:
        raise ValueError("user does not have permissions configured")


@register.filter
def has_object_permission(obj, permission):
    return user_has_permission(crum.get_current_user(), obj, Permissions[permission])


@register.filter
def has_global_permission(permission):
    return user_has_global_permission(crum.get_current_user(), Permissions[permission])


@register.filter
def has_configuration_permission(permission, request):
    if request is None:
        user = crum.get_current_user()
    else:
        user = crum.get_current_user() or request.user
    return configuration_permission(user, permission)


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


@register.simple_tag
def user_can_clear_peer_review(finding, user):
    finding_under_review = finding.under_review
    user_requesting_review = user == finding.review_requested_by
    user_is_reviewer = user in finding.reviewers.all()
    return finding_under_review and (user_requesting_review or user_is_reviewer)
