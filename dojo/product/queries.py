from crum import get_current_user
from django.db.models import Q, Subquery

from dojo.authorization.authorization import (
    get_roles_for_permission,
    role_has_permission,
    user_has_global_permission,
    user_has_permission,
)
from dojo.authorization.roles_permissions import Permissions
from dojo.group.queries import get_authorized_groups
from dojo.models import (
    App_Analysis,
    DojoMeta,
    Engagement_Presets,
    Global_Role,
    Languages,
    Product,
    Product_API_Scan_Configuration,
    Product_Group,
    Product_Member,
    Product_Type_Group,
    Product_Type_Member,
)
from dojo.request_cache import cache_for_request


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_products(permission, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return Product.objects.none()

    if user.is_superuser:
        return Product.objects.all().order_by("name")

    if user_has_global_permission(user, permission):
        return Product.objects.all().order_by("name")

    roles = get_roles_for_permission(permission)

    # Get authorized product/product_type IDs via subqueries
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_roles = Product_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_id")

    authorized_product_type_groups = Product_Type_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_groups = Product_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_id")

    # Filter using IN with Subquery - no annotations needed
    return Product.objects.filter(
        Q(prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(pk__in=Subquery(authorized_product_roles))
        | Q(prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(pk__in=Subquery(authorized_product_groups)),
    ).order_by("name")


def get_authorized_members_for_product(product, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product, permission):
        return Product_Member.objects.filter(product=product).order_by("user__first_name", "user__last_name").select_related("role", "user")
    return Product_Member.objects.none()


def get_authorized_global_members_for_product(product, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product, permission):
        return Global_Role.objects.filter(group=None, role__isnull=False).order_by("user__first_name", "user__last_name").select_related("role", "user")
    return Global_Role.objects.none()


def get_authorized_groups_for_product(product, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product, permission):
        authorized_groups = get_authorized_groups(Permissions.Group_View)
        return Product_Group.objects.filter(product=product, group__in=authorized_groups).order_by("group__name").select_related("role")
    return Product_Group.objects.none()


def get_authorized_global_groups_for_product(product, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product, permission):
        return Global_Role.objects.filter(user=None, role__isnull=False).order_by("group__name").select_related("role")
    return Global_Role.objects.none()


def get_authorized_product_members(permission):
    user = get_current_user()

    if user is None:
        return Product_Member.objects.none()

    if user.is_superuser:
        return Product_Member.objects.all().order_by("id").select_related("role")

    if user_has_global_permission(user, permission):
        return Product_Member.objects.all().order_by("id").select_related("role")

    products = get_authorized_products(permission)
    return Product_Member.objects.filter(product__in=products).order_by("id").select_related("role")


def get_authorized_product_members_for_user(user, permission):
    request_user = get_current_user()

    if request_user is None:
        return Product_Member.objects.none()

    if request_user.is_superuser:
        return Product_Member.objects.filter(user=user).select_related("role", "product")

    if hasattr(request_user, "global_role") and request_user.global_role.role is not None and role_has_permission(request_user.global_role.role.id, permission):
        return Product_Member.objects.filter(user=user).select_related("role", "product")

    products = get_authorized_products(permission)
    return Product_Member.objects.filter(user=user, product__in=products).select_related("role", "product")


def get_authorized_product_groups(permission):
    user = get_current_user()

    if user is None:
        return Product_Group.objects.none()

    if user.is_superuser:
        return Product_Group.objects.all().order_by("id").select_related("role")

    products = get_authorized_products(permission)
    return Product_Group.objects.filter(product__in=products).order_by("id").select_related("role")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_app_analysis(permission):
    user = get_current_user()

    if user is None:
        return App_Analysis.objects.none()

    if user.is_superuser:
        return App_Analysis.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return App_Analysis.objects.all().order_by("id")

    roles = get_roles_for_permission(permission)

    # Get authorized product/product_type IDs via subqueries
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_roles = Product_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_id")

    authorized_product_type_groups = Product_Type_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_groups = Product_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_id")

    # Filter using IN with Subquery - no annotations needed
    return App_Analysis.objects.filter(
        Q(product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(product_id__in=Subquery(authorized_product_roles))
        | Q(product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(product_id__in=Subquery(authorized_product_groups)),
    ).order_by("id")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_dojo_meta(permission):
    user = get_current_user()

    if user is None:
        return DojoMeta.objects.none()

    if user.is_superuser:
        return DojoMeta.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return DojoMeta.objects.all().order_by("id")

    roles = get_roles_for_permission(permission)

    # Get authorized product/product_type IDs via subqueries for all three paths
    # Product path
    product_authorized_product_type_roles = Product_Type_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_type_id")

    product_authorized_product_roles = Product_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_id")

    product_authorized_product_type_groups = Product_Type_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_type_id")

    product_authorized_product_groups = Product_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_id")

    # Filter using IN with Subquery - no annotations needed
    # DojoMeta can be attached to product, endpoint, or finding
    return DojoMeta.objects.filter(
        # Product path
        Q(product__prod_type_id__in=Subquery(product_authorized_product_type_roles))
        | Q(product_id__in=Subquery(product_authorized_product_roles))
        | Q(product__prod_type_id__in=Subquery(product_authorized_product_type_groups))
        | Q(product_id__in=Subquery(product_authorized_product_groups))
        # Endpoint path
        | Q(endpoint__product__prod_type_id__in=Subquery(product_authorized_product_type_roles))
        | Q(endpoint__product_id__in=Subquery(product_authorized_product_roles))
        | Q(endpoint__product__prod_type_id__in=Subquery(product_authorized_product_type_groups))
        | Q(endpoint__product_id__in=Subquery(product_authorized_product_groups))
        # Finding path
        | Q(finding__test__engagement__product__prod_type_id__in=Subquery(product_authorized_product_type_roles))
        | Q(finding__test__engagement__product_id__in=Subquery(product_authorized_product_roles))
        | Q(finding__test__engagement__product__prod_type_id__in=Subquery(product_authorized_product_type_groups))
        | Q(finding__test__engagement__product_id__in=Subquery(product_authorized_product_groups)),
    ).order_by("id")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_languages(permission):
    user = get_current_user()

    if user is None:
        return Languages.objects.none()

    if user.is_superuser:
        return Languages.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Languages.objects.all().order_by("id")

    roles = get_roles_for_permission(permission)

    # Get authorized product/product_type IDs via subqueries
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_roles = Product_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_id")

    authorized_product_type_groups = Product_Type_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_groups = Product_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_id")

    # Filter using IN with Subquery - no annotations needed
    return Languages.objects.filter(
        Q(product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(product_id__in=Subquery(authorized_product_roles))
        | Q(product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(product_id__in=Subquery(authorized_product_groups)),
    ).order_by("id")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_engagement_presets(permission):
    user = get_current_user()

    if user is None:
        return Engagement_Presets.objects.none()

    if user.is_superuser:
        return Engagement_Presets.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Engagement_Presets.objects.all().order_by("id")

    roles = get_roles_for_permission(permission)

    # Get authorized product/product_type IDs via subqueries
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_roles = Product_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_id")

    authorized_product_type_groups = Product_Type_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_groups = Product_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_id")

    # Filter using IN with Subquery - no annotations needed
    return Engagement_Presets.objects.filter(
        Q(product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(product_id__in=Subquery(authorized_product_roles))
        | Q(product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(product_id__in=Subquery(authorized_product_groups)),
    ).order_by("id")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_product_api_scan_configurations(permission):
    user = get_current_user()

    if user is None:
        return Product_API_Scan_Configuration.objects.none()

    if user.is_superuser:
        return Product_API_Scan_Configuration.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Product_API_Scan_Configuration.objects.all().order_by("id")

    roles = get_roles_for_permission(permission)

    # Get authorized product/product_type IDs via subqueries
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_roles = Product_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_id")

    authorized_product_type_groups = Product_Type_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_groups = Product_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_id")

    # Filter using IN with Subquery - no annotations needed
    return Product_API_Scan_Configuration.objects.filter(
        Q(product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(product_id__in=Subquery(authorized_product_roles))
        | Q(product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(product_id__in=Subquery(authorized_product_groups)),
    ).order_by("id")
