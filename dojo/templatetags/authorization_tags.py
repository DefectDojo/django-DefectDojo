import crum
from django import template

from dojo.authorization.authorization import user_has_configuration_permission as configuration_permission
from dojo.authorization.authorization import user_has_global_permission, user_has_permission
from dojo.authorization.exclusive_permissions import user_has_exclusive_permission_product
from dojo.authorization.roles_permissions import Permissions
from dojo.risk_acceptance.risk_pending import is_permissions_risk_acceptance 
from dojo.utils import get_product
from dojo.request_cache import cache_for_request
import dojo.risk_acceptance.helper as helper_ra
import dojo.transfer_findings.helper as helper_tf

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
    user = crum.get_current_user() if request is None else crum.get_current_user() or request.user
    return configuration_permission(user, permission)


@cache_for_request
def get_user_permissions(user):
    return user.user_permissions.all()


@register.filter
def user_has_configuration_permission_without_group(user, codename):
    permissions = get_user_permissions(user)
    return any(permission.codename == codename for permission in permissions)


@cache_for_request
def get_group_permissions(group):
    return group.permissions.all()


@register.filter
def group_has_configuration_permission(group, codename):
    return any(permission.codename == codename for permission in get_group_permissions(group))


@register.simple_tag
def user_can_clear_peer_review(finding, user):
    finding_under_review = finding.under_review
    user_requesting_review = user == finding.review_requested_by
    user_is_reviewer = user in finding.reviewers.all()
    return finding_under_review and (user_requesting_review or user_is_reviewer)


@register.filter
def enable_button(finding, button):
    button_dict = {
        "Add Risk Acceptance": helper_ra.enable_flow_accept_risk,
        "Add Transfer Finding": helper_tf.enable_flow_transfer_finding,
    }
    if button in button_dict and isinstance(button, str):
        function_action = button_dict[button]
        return function_action(finding=finding)
    else:
        raise ValueError("Not implemented rules button")

@register.filter
def has_object_exclusive_permission(obj, permission):
    return user_has_exclusive_permission_product(crum.get_current_user(), obj, Permissions[permission])     
