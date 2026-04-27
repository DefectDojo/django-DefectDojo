try:
    from dojo.authorization.query_filters import get_auth_filter
except ImportError:
    def get_auth_filter(key): return None

try:
    from dojo.authorization.models import (
        Global_Role,
        Product_Group,
        Product_Member,
    )
except ImportError:
    Global_Role = None
    Product_Group = None
    Product_Member = None

from dojo.models import (
    App_Analysis,
    DojoMeta,
    Engagement_Presets,
    Languages,
    Product,
    Product_API_Scan_Configuration,
)
from dojo.request_cache import cache_for_request


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_products(permission, user=None):
    impl = get_auth_filter("product.get_authorized_products")
    if impl:
        return impl(permission, user=user)
    return Product.objects.all().order_by("name")


def get_authorized_members_for_product(product, permission):
    impl = get_auth_filter("product.get_authorized_members_for_product")
    if impl:
        return impl(product, permission)
    return Product_Member.objects.filter(product=product).order_by("user__first_name", "user__last_name").select_related("role", "user")


def get_authorized_global_members_for_product(product, permission):
    impl = get_auth_filter("product.get_authorized_global_members_for_product")
    if impl:
        return impl(product, permission)
    return Global_Role.objects.filter(group=None, role__isnull=False).order_by("user__first_name", "user__last_name").select_related("role", "user")


def get_authorized_groups_for_product(product, permission):
    impl = get_auth_filter("product.get_authorized_groups_for_product")
    if impl:
        return impl(product, permission)
    return Product_Group.objects.filter(product=product).order_by("group__name").select_related("role")


def get_authorized_global_groups_for_product(product, permission):
    impl = get_auth_filter("product.get_authorized_global_groups_for_product")
    if impl:
        return impl(product, permission)
    return Global_Role.objects.filter(user=None, role__isnull=False).order_by("group__name").select_related("role")


def get_authorized_product_members(permission):
    impl = get_auth_filter("product.get_authorized_product_members")
    if impl:
        return impl(permission)
    return Product_Member.objects.all().order_by("id").select_related("role")


def get_authorized_product_members_for_user(user, permission):
    impl = get_auth_filter("product.get_authorized_product_members_for_user")
    if impl:
        return impl(user, permission)
    return Product_Member.objects.filter(user=user).select_related("role", "product")


def get_authorized_product_groups(permission):
    impl = get_auth_filter("product.get_authorized_product_groups")
    if impl:
        return impl(permission)
    return Product_Group.objects.all().order_by("id").select_related("role")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_app_analysis(permission):
    impl = get_auth_filter("product.get_authorized_app_analysis")
    if impl:
        return impl(permission)
    return App_Analysis.objects.all().order_by("id")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_dojo_meta(permission):
    impl = get_auth_filter("product.get_authorized_dojo_meta")
    if impl:
        return impl(permission)
    return DojoMeta.objects.all().order_by("id")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_languages(permission):
    impl = get_auth_filter("product.get_authorized_languages")
    if impl:
        return impl(permission)
    return Languages.objects.all().order_by("id")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_engagement_presets(permission):
    impl = get_auth_filter("product.get_authorized_engagement_presets")
    if impl:
        return impl(permission)
    return Engagement_Presets.objects.all().order_by("id")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_product_api_scan_configurations(permission):
    impl = get_auth_filter("product.get_authorized_product_api_scan_configurations")
    if impl:
        return impl(permission)
    return Product_API_Scan_Configuration.objects.all().order_by("id")
