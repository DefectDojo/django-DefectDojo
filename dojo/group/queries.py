try:
    from dojo.authorization.query_filters import get_auth_filter
except ImportError:
    def get_auth_filter(key): return None

try:
    from dojo.authorization.models import Dojo_Group_Member, Product_Group, Product_Type_Group, Role
except ImportError:
    Dojo_Group_Member = None
    Product_Group = None
    Product_Type_Group = None
    Role = None

from dojo.models import Dojo_Group
from dojo.request_cache import cache_for_request


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_groups(permission):
    impl = get_auth_filter("group.get_authorized_groups")
    if impl:
        return impl(permission)
    return Dojo_Group.objects.all().order_by("name")


def get_authorized_group_members(permission):
    impl = get_auth_filter("group.get_authorized_group_members")
    if impl:
        return impl(permission)
    return Dojo_Group_Member.objects.all().order_by("id").select_related("role")


def get_authorized_group_members_for_user(user):
    impl = get_auth_filter("group.get_authorized_group_members_for_user")
    if impl:
        return impl(user)
    return Dojo_Group_Member.objects.filter(user=user).order_by("group__name").select_related("role", "group")


def get_group_members_for_group(group):
    return Dojo_Group_Member.objects.filter(group=group).select_related("role")


def get_product_groups_for_group(group):
    return Product_Group.objects.filter(group=group).select_related("role")


def get_product_type_groups_for_group(group):
    return Product_Type_Group.objects.filter(group=group).select_related("role")


def get_group_member_roles():
    return Role.objects.exclude(name="API_Importer").exclude(name="Writer")
