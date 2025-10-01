from dojo.authorization.roles_permissions import Roles, get_roles_with_permissions
from dojo.authorization.exclusive_permissions import get_members


def get_global_role(user):
    if hasattr(user, "global_role"):
        if user.global_role:
            if user.global_role.role:
                if user.global_role.role.name in Roles.get_roles():
                    return user.global_role.role.name

def user_has_permission(user, obj):
    if user.is_anonymous:
        return []

    if user.is_superuser:
        return ["all"]
    role = get_global_role(user)
    if role is None:
        members = get_members(user, obj)
        if members:
            role = members.role.name
        else:
            return []
    roles = get_roles_with_permissions()
    permissions = roles.get(Roles[role])
    return permissions
