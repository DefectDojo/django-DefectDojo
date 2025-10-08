import crum
from dojo.models import GeneralSettings
from dojo.templatetags.authorization_tags import enable_button
from dojo.authorization.roles_permissions import Permissions
from dojo.user.queries import get_role_members
from dojo.authorization.authorization_api import user_has_permission
import dojo.risk_acceptance.helper as helper_ra
import dojo.finding.helper as helper_f
import dojo.transfer_findings.helper as helper_tf

def get_permissions(obj):
    if GeneralSettings.get_value("ENABLE_PERMISSIONS_API", False):
        user = crum.get_current_user()
        permissions = user_has_permission(user, obj)
        if permissions is False:
            return []
        if "all" not in permissions:
            permissions = [perm.name for perm in permissions]
        return validation_status_permission(obj, permissions) 
    return []

def enable_permission(obj, permission, return_value=False):
    permissions = get_permissions(obj)
    return enable_button(permissions, permission)

def validation_status_permission(finding, permissions):
    button_dict = {
        "Risk_Acceptance": helper_ra.enable_flow_accept_risk,
        "Transfer_Finding_Add": helper_tf.enable_flow_transfer_finding,
        "Transfer_Finding_Finding_Add": helper_tf.enable_flow_transfer_finding,
    }

    for perm in permissions[:]:
        if perm in button_dict:
            function_action = button_dict[perm]
            if not function_action(finding=finding):
                permissions.remove(perm)

    return permissions