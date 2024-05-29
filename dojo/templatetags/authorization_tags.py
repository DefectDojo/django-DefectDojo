from django import template
import crum
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.authorization import user_has_global_permission, user_has_permission, \
    user_has_configuration_permission as configuration_permission
from dojo.risk_acceptance.risk_pending import is_permissions_risk_acceptance 
from dojo.utils import get_product
from dojo.request_cache import cache_for_request

register = template.Library()



@register.filter
def has_risk_acceptance_pending(engagement, findings):
    user = crum.get_current_user()
    product = get_product(engagement)
    product_type = product.get_product_type
    for finding in findings:
        if is_permissions_risk_acceptance(engagement, finding, user, product, product_type):
            return True
            
        
@register.filter
def has_risk_acceptance_permission(engagement, finding):
    user = crum.get_current_user()
    product = get_product(engagement)
    product_type = product.get_product_type
    return is_permissions_risk_acceptance(engagement, finding, user, product, product_type)

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
