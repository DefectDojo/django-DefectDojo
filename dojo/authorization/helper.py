import crum
from dojo.models import GeneralSettings
from dojo.authorization.roles_permissions import Permissions
from dojo.user.queries import get_role_members
from dojo.authorization.authorization_api import user_has_permission

def get_permissions(obj):
    if GeneralSettings.get_value("ENABLE_PERMISSIONS_API", False):
        user = crum.get_current_user()
        permissions = user_has_permission(user, obj)
        if permissions is False:
            return []
        if "all" not in permissions:
            permissions = [perm.name for perm in permissions]
        return permissions
    return []
