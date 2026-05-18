from django import template

from dojo.authorization.template_filters import (
    group_has_configuration_permission,
    has_configuration_permission,
    has_global_permission,
    has_object_permission,
    user_can_clear_peer_review,
    user_has_configuration_permission_without_group,
)

register = template.Library()

register.filter("has_object_permission", has_object_permission)
register.filter("has_global_permission", has_global_permission)
register.filter("has_configuration_permission", has_configuration_permission)
register.filter("user_has_configuration_permission_without_group", user_has_configuration_permission_without_group)
register.filter("group_has_configuration_permission", group_has_configuration_permission)
register.simple_tag(user_can_clear_peer_review, name="user_can_clear_peer_review")
