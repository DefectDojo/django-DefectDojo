from crum import get_current_user
from dojo.risk_acceptance import risk_pending
from dojo.authorization.authorization import (
    user_has_global_permission,
    user_has_permission,
    user_has_configuration_permission,
)

def get_permissions_tranfer_finding(permission):
    user = get_current_user()
    role = risk_pending.get_role_members(user, obj_producto, obj_product_type)
    permission_result = user_has_global_permission(user, permission)
    roles = roles_permissions.get_roles_with_permissions()




