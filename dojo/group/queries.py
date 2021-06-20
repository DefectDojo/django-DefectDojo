from crum import get_current_user
from django.db.models import Exists, OuterRef
from django.conf import settings
from dojo.models import Dojo_Group, Dojo_Group_User
from dojo.authorization.authorization import get_roles_for_permission, role_has_permission, get_groups


def get_authorized_groups(permission):
    user = get_current_user()

    if user is None:
        return Dojo_Group.objects.none()

    if user.is_superuser:
        return Dojo_Group.objects.all().order_by('name')

    if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
        return Dojo_Group.objects.all().order_by('name')

    if hasattr(user, 'global_role') and role_has_permission(user.global_role.role.id, permission):
        return Dojo_Group.objects.all().order_by('name')

    for group in get_groups(user):
        if hasattr(group, 'global_role') and role_has_permission(group.global_role.role.id, permission):
            return Dojo_Group.objects.all().order_by('name')

    roles = get_roles_for_permission(permission)
    authorized_roles = Dojo_Group_User.objects.filter(dojo_group=OuterRef('pk'),
        user=user,
        role__in=roles)
    groups = Dojo_Group.objects.annotate(user=Exists(authorized_roles)).order_by('name')
    return groups.filter(user=True)


def get_authorized_group_users(permission):
    user = get_current_user()

    if user is None:
        return Dojo_Group_User.objects.none()

    if user.is_superuser:
        return Dojo_Group_User.objects.all()

    if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
        return Dojo_Group_User.objects.all()

    if hasattr(user, 'global_role') and role_has_permission(user.global_role.role.id, permission):
        return Dojo_Group_User.objects.all()

    groups = get_authorized_groups(permission)
    return Dojo_Group_User.objects.filter(dojo_group__in=groups)
