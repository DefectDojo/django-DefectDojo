import crum

from dojo.authorization.authorization import user_has_configuration_permission as configuration_permission
from dojo.authorization.authorization import user_has_global_permission, user_has_permission
from dojo.request_cache import cache_for_request


def has_object_permission(obj, permission):
    # Pass-through to user_has_permission(); permission_to_action() inside the
    # legacy authorization layer accepts both the new action strings ("view",
    # "edit", ...) and any leftover Permissions enum names ("Product_Edit", ...).
    return user_has_permission(crum.get_current_user(), obj, permission)


def has_global_permission(permission):
    return user_has_global_permission(crum.get_current_user(), permission)


def has_configuration_permission(permission, request):
    user = crum.get_current_user() if request is None else crum.get_current_user() or request.user
    return configuration_permission(user, permission)


@cache_for_request
def get_user_permissions(user):
    return user.user_permissions.all()


def user_has_configuration_permission_without_group(user, codename):
    permissions = get_user_permissions(user)
    return any(permission.codename == codename for permission in permissions)


@cache_for_request
def get_group_permissions(group):
    return group.permissions.all()


def group_has_configuration_permission(group, codename):
    return any(permission.codename == codename for permission in get_group_permissions(group))


def user_can_clear_peer_review(finding, user):
    finding_under_review = finding.under_review
    user_requesting_review = user == finding.review_requested_by
    user_is_reviewer = user in finding.reviewers.all()
    return finding_under_review and (user_requesting_review or user_is_reviewer)
