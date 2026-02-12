from crum import get_current_user
from django.db.models import Subquery

from dojo.authorization.authorization import get_roles_for_permission, user_has_configuration_permission
from dojo.authorization.roles_permissions import Permissions
from dojo.models import Dojo_Group, Dojo_Group_Member, Product_Group, Product_Type_Group, Role
from dojo.request_cache import cache_for_request


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_groups(permission):
    user = get_current_user()

    if user is None:
        return Dojo_Group.objects.none()

    if user.is_superuser:
        return Dojo_Group.objects.all().order_by("name")

    # Check for the case of the view_group config permission
    if user_has_configuration_permission(user, "auth.view_group") or user_has_configuration_permission(user, "auth.add_group"):
        return Dojo_Group.objects.all().order_by("name")

    roles = get_roles_for_permission(permission)

    # Get authorized group IDs via subquery
    authorized_roles = Dojo_Group_Member.objects.filter(
        user=user, role__in=roles,
    ).values("group_id")

    # Filter using IN with Subquery - no annotations needed
    return Dojo_Group.objects.filter(
        pk__in=Subquery(authorized_roles),
    ).order_by("name")


def get_authorized_group_members(permission):
    user = get_current_user()

    if user is None:
        return Dojo_Group_Member.objects.none()

    if user.is_superuser:
        return Dojo_Group_Member.objects.all().order_by("id").select_related("role")

    groups = get_authorized_groups(permission)
    return Dojo_Group_Member.objects.filter(group__in=groups).order_by("id").select_related("role")


def get_authorized_group_members_for_user(user):
    groups = get_authorized_groups(Permissions.Group_View)
    return Dojo_Group_Member.objects.filter(user=user, group__in=groups).order_by("group__name").select_related("role", "group")


def get_group_members_for_group(group):
    return Dojo_Group_Member.objects.filter(group=group).select_related("role")


def get_product_groups_for_group(group):
    return Product_Group.objects.filter(group=group).select_related("role")


def get_product_type_groups_for_group(group):
    return Product_Type_Group.objects.filter(group=group).select_related("role")


def get_group_member_roles():
    return Role.objects.exclude(name="API_Importer").exclude(name="Writer")
