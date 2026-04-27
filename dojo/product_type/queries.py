try:
    from dojo.authorization.query_filters import get_auth_filter
except ImportError:
    def get_auth_filter(key): return None

try:
    from dojo.authorization.models import Global_Role, Product_Type_Group, Product_Type_Member
except ImportError:
    Global_Role = None
    Product_Type_Group = None
    Product_Type_Member = None

from dojo.models import Product_Type
from dojo.request_cache import cache_for_request


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_product_types(permission):
    impl = get_auth_filter("product_type.get_authorized_product_types")
    if impl:
        return impl(permission)
    return Product_Type.objects.all().order_by("name")


def get_authorized_members_for_product_type(product_type, permission):
    impl = get_auth_filter("product_type.get_authorized_members_for_product_type")
    if impl:
        return impl(product_type, permission)
    return Product_Type_Member.objects.filter(product_type=product_type).order_by("user__first_name", "user__last_name").select_related("role", "product_type", "user")


def get_authorized_global_members_for_product_type(product_type, permission):
    impl = get_auth_filter("product_type.get_authorized_global_members_for_product_type")
    if impl:
        return impl(product_type, permission)
    return Global_Role.objects.filter(group=None, role__isnull=False).order_by("user__first_name", "user__last_name").select_related("role", "user")


def get_authorized_groups_for_product_type(product_type, permission):
    impl = get_auth_filter("product_type.get_authorized_groups_for_product_type")
    if impl:
        return impl(product_type, permission)
    return Product_Type_Group.objects.filter(product_type=product_type).order_by("group__name").select_related("role", "group")


def get_authorized_global_groups_for_product_type(product_type, permission):
    impl = get_auth_filter("product_type.get_authorized_global_groups_for_product_type")
    if impl:
        return impl(product_type, permission)
    return Global_Role.objects.filter(user=None, role__isnull=False).order_by("group__name").select_related("role", "group")


def get_authorized_product_type_members(permission):
    impl = get_auth_filter("product_type.get_authorized_product_type_members")
    if impl:
        return impl(permission)
    return Product_Type_Member.objects.all().order_by("id").select_related("role")


def get_authorized_product_type_members_for_user(user, permission):
    impl = get_auth_filter("product_type.get_authorized_product_type_members_for_user")
    if impl:
        return impl(user, permission)
    return Product_Type_Member.objects.filter(user=user).select_related("role", "product_type")


def get_authorized_product_type_groups(permission):
    impl = get_auth_filter("product_type.get_authorized_product_type_groups")
    if impl:
        return impl(permission)
    return Product_Type_Group.objects.all().order_by("id").select_related("role")
