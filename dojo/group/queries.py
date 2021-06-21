from crum import get_current_user
from django.db.models import Exists, OuterRef
from django.conf import settings
from dojo.models import Dojo_Group, Dojo_Group_User, Product_Group, Product_Type_Group
from dojo.authorization.authorization import get_roles_for_permission, role_has_permission, get_groups
from dojo.authorization.roles_permissions import Permissions


def get_authorized_groups(permission):
    user = get_current_user()

    if user is None:
        return Dojo_Group.objects.none()

    if user.is_superuser:
        return Dojo_Group.objects.all().order_by('name')

    if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
        return Dojo_Group.objects.all().order_by('name')

    if hasattr(user, 'global_role') and user.global_role.role is not None and role_has_permission(user.global_role.role.id, permission):
        return Dojo_Group.objects.all().order_by('name')

    for group in get_groups(user):
        if hasattr(group, 'global_role') and group.global_role.role is not None and role_has_permission(group.global_role.role.id, permission):
            return Dojo_Group.objects.all().order_by('name')

    roles = get_roles_for_permission(permission)
    authorized_roles = Dojo_Group_User.objects.filter(group=OuterRef('pk'),
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

    if hasattr(user, 'global_role') and user.global_role.role is not None and role_has_permission(user.global_role.role.id, permission):
        return Dojo_Group_User.objects.all()

    groups = get_authorized_groups(permission)
    return Dojo_Group_User.objects.filter(group__in=groups)


def get_authorized_group_users_for_user(user):
    groups = get_authorized_groups(Permissions.Group_View)
    groups = Dojo_Group_User.objects.filter(user=user, group__in=groups)
    return groups


def get_group_users_for_group(group):
    return Dojo_Group_User.objects.filter(group=group)


def get_product_groups_for_group(group):
    return Product_Group.objects.filter(group=group)


def get_product_type_groups_for_group(group):
    return Product_Type_Group.objects.filter(group=group)
