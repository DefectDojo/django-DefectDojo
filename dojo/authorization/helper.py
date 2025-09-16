import crum
from dojo.authorization.roles_permissions import Permissions
from dojo.user.queries import get_role_members
from dojo.authorization.authorization_api import user_has_permission

def get_permissions(obj):
    user = crum.get_current_user()
    permissions = user_has_permission(user, obj, Permissions.Finding_View)
    if permissions is False:
        return []
    if "all" not in permissions:
        permissions = [perm.name for perm in permissions]
    return permissions