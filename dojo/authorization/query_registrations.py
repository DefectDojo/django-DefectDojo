from crum import get_current_user
from django.db.models import Exists, OuterRef, Q, Subquery

from dojo.authorization.authorization import (
    get_roles_for_permission,
    role_has_permission,
    user_has_configuration_permission,
    user_has_global_permission,
    user_has_permission,
)
from dojo.authorization.models import (
    Dojo_Group_Member,
    Global_Role,
    Product_Group,
    Product_Member,
    Product_Type_Group,
    Product_Type_Member,
)
from dojo.authorization.query_filters import register_auth_filter
from dojo.authorization.roles_permissions import Permissions
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.models import (
    App_Analysis,
    Cred_Mapping,
    Dojo_Group,
    Dojo_User,
    DojoMeta,
    Endpoint,
    Endpoint_Status,
    Engagement,
    Engagement_Presets,
    Finding,
    Finding_Group,
    JIRA_Issue,
    JIRA_Project,
    Languages,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Risk_Acceptance,
    Stub_Finding,
    Test,
    Test_Import,
    Tool_Product_Settings,
    Vulnerability_Id,
)

# ============================================================================
# Product queries
# ============================================================================


def _get_authorized_products(permission, user=None):

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


register_auth_filter("product.get_authorized_products", _get_authorized_products)


def _get_authorized_members_for_product(product, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product, permission):
        return Product_Member.objects.filter(product=product).order_by("user__first_name", "user__last_name").select_related("role", "user")
    return Product_Member.objects.none()


register_auth_filter("product.get_authorized_members_for_product", _get_authorized_members_for_product)


def _get_authorized_global_members_for_product(product, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product, permission):
        return Global_Role.objects.filter(group=None, role__isnull=False).order_by("user__first_name", "user__last_name").select_related("role", "user")
    return Global_Role.objects.none()


register_auth_filter("product.get_authorized_global_members_for_product", _get_authorized_global_members_for_product)


def _get_authorized_groups_for_product(product, permission):
    from dojo.group.queries import get_authorized_groups  # noqa: PLC0415

    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product, permission):
        authorized_groups = get_authorized_groups(Permissions.Group_View)
        return Product_Group.objects.filter(product=product, group__in=authorized_groups).order_by("group__name").select_related("role")
    return Product_Group.objects.none()


register_auth_filter("product.get_authorized_groups_for_product", _get_authorized_groups_for_product)


def _get_authorized_global_groups_for_product(product, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product, permission):
        return Global_Role.objects.filter(user=None, role__isnull=False).order_by("group__name").select_related("role")
    return Global_Role.objects.none()


register_auth_filter("product.get_authorized_global_groups_for_product", _get_authorized_global_groups_for_product)


def _get_authorized_product_members(permission):
    from dojo.product.queries import get_authorized_products  # noqa: PLC0415

    user = get_current_user()

    if user is None:
        return Product_Member.objects.none()

    if user.is_superuser:
        return Product_Member.objects.all().order_by("id").select_related("role")

    if user_has_global_permission(user, permission):
        return Product_Member.objects.all().order_by("id").select_related("role")

    products = get_authorized_products(permission)
    return Product_Member.objects.filter(product__in=products).order_by("id").select_related("role")


register_auth_filter("product.get_authorized_product_members", _get_authorized_product_members)


def _get_authorized_product_members_for_user(user, permission):
    from dojo.product.queries import get_authorized_products  # noqa: PLC0415

    request_user = get_current_user()

    if request_user is None:
        return Product_Member.objects.none()

    if request_user.is_superuser:
        return Product_Member.objects.filter(user=user).select_related("role", "product")

    if hasattr(request_user, "global_role") and request_user.global_role.role is not None and role_has_permission(request_user.global_role.role.id, permission):
        return Product_Member.objects.filter(user=user).select_related("role", "product")

    products = get_authorized_products(permission)
    return Product_Member.objects.filter(user=user, product__in=products).select_related("role", "product")


register_auth_filter("product.get_authorized_product_members_for_user", _get_authorized_product_members_for_user)


def _get_authorized_product_groups(permission):
    from dojo.product.queries import get_authorized_products  # noqa: PLC0415

    user = get_current_user()

    if user is None:
        return Product_Group.objects.none()

    if user.is_superuser:
        return Product_Group.objects.all().order_by("id").select_related("role")

    products = get_authorized_products(permission)
    return Product_Group.objects.filter(product__in=products).order_by("id").select_related("role")


register_auth_filter("product.get_authorized_product_groups", _get_authorized_product_groups)


def _get_authorized_app_analysis(permission):
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


register_auth_filter("product.get_authorized_app_analysis", _get_authorized_app_analysis)


def _get_authorized_dojo_meta(permission):
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


register_auth_filter("product.get_authorized_dojo_meta", _get_authorized_dojo_meta)


def _get_authorized_languages(permission):
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


register_auth_filter("product.get_authorized_languages", _get_authorized_languages)


def _get_authorized_engagement_presets(permission):
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


register_auth_filter("product.get_authorized_engagement_presets", _get_authorized_engagement_presets)


def _get_authorized_product_api_scan_configurations(permission):
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


register_auth_filter("product.get_authorized_product_api_scan_configurations", _get_authorized_product_api_scan_configurations)


# ============================================================================
# Product Type queries
# ============================================================================

def _get_authorized_product_types(permission):
    user = get_current_user()

    if user is None:
        return Product_Type.objects.none()

    if user.is_superuser:
        return Product_Type.objects.all().order_by("name")

    if user_has_global_permission(user, permission):
        return Product_Type.objects.all().order_by("name")

    roles = get_roles_for_permission(permission)

    # Get authorized product_type IDs via subqueries
    authorized_roles = Product_Type_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_type_id")

    authorized_groups = Product_Type_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_type_id")

    # Filter using IN with Subquery - no annotations needed
    return Product_Type.objects.filter(
        Q(pk__in=Subquery(authorized_roles))
        | Q(pk__in=Subquery(authorized_groups)),
    ).order_by("name")


register_auth_filter("product_type.get_authorized_product_types", _get_authorized_product_types)


def _get_authorized_members_for_product_type(product_type, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product_type, permission):
        return Product_Type_Member.objects.filter(product_type=product_type).order_by("user__first_name", "user__last_name").select_related("role", "product_type", "user")
    return Product_Type_Member.objects.none()


register_auth_filter("product_type.get_authorized_members_for_product_type", _get_authorized_members_for_product_type)


def _get_authorized_global_members_for_product_type(product_type, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product_type, permission):
        return Global_Role.objects.filter(group=None, role__isnull=False).order_by("user__first_name", "user__last_name").select_related("role", "user")
    return Global_Role.objects.none()


register_auth_filter("product_type.get_authorized_global_members_for_product_type", _get_authorized_global_members_for_product_type)


def _get_authorized_groups_for_product_type(product_type, permission):
    from dojo.group.queries import get_authorized_groups  # noqa: PLC0415

    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product_type, permission):
        authorized_groups = get_authorized_groups(Permissions.Group_View)
        return Product_Type_Group.objects.filter(product_type=product_type, group__in=authorized_groups).order_by("group__name").select_related("role", "group")
    return Product_Type_Group.objects.none()


register_auth_filter("product_type.get_authorized_groups_for_product_type", _get_authorized_groups_for_product_type)


def _get_authorized_global_groups_for_product_type(product_type, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product_type, permission):
        return Global_Role.objects.filter(user=None, role__isnull=False).order_by("group__name").select_related("role", "group")
    return Global_Role.objects.none()


register_auth_filter("product_type.get_authorized_global_groups_for_product_type", _get_authorized_global_groups_for_product_type)


def _get_authorized_product_type_members(permission):
    from dojo.product_type.queries import get_authorized_product_types  # noqa: PLC0415

    user = get_current_user()

    if user is None:
        return Product_Type_Member.objects.none()

    if user.is_superuser:
        return Product_Type_Member.objects.all().order_by("id").select_related("role")

    if user_has_global_permission(user, permission):
        return Product_Type_Member.objects.all().order_by("id").select_related("role")

    product_types = get_authorized_product_types(permission)
    return Product_Type_Member.objects.filter(product_type__in=product_types).order_by("id").select_related("role")


register_auth_filter("product_type.get_authorized_product_type_members", _get_authorized_product_type_members)


def _get_authorized_product_type_members_for_user(user, permission):
    from dojo.product_type.queries import get_authorized_product_types  # noqa: PLC0415

    request_user = get_current_user()

    if request_user is None:
        return Product_Type_Member.objects.none()

    if request_user.is_superuser:
        return Product_Type_Member.objects.filter(user=user).select_related("role", "product_type")

    if hasattr(request_user, "global_role") and request_user.global_role.role is not None and role_has_permission(request_user.global_role.role.id, permission):
        return Product_Type_Member.objects.filter(user=user).select_related("role", "product_type")

    product_types = get_authorized_product_types(permission)
    return Product_Type_Member.objects.filter(user=user, product_type__in=product_types).select_related("role", "product_type")


register_auth_filter("product_type.get_authorized_product_type_members_for_user", _get_authorized_product_type_members_for_user)


def _get_authorized_product_type_groups(permission):
    from dojo.product_type.queries import get_authorized_product_types  # noqa: PLC0415

    user = get_current_user()

    if user is None:
        return Product_Type_Group.objects.none()

    if user.is_superuser:
        return Product_Type_Group.objects.all().order_by("id").select_related("role")

    product_types = get_authorized_product_types(permission)
    return Product_Type_Group.objects.filter(product_type__in=product_types).order_by("id").select_related("role")


register_auth_filter("product_type.get_authorized_product_type_groups", _get_authorized_product_type_groups)


# ============================================================================
# Finding queries
# ============================================================================

def _get_authorized_findings(permission, user=None):
    """Cached - returns all findings the user is authorized to see."""
    if user is None:
        user = get_current_user()
    if user is None:
        return Finding.objects.none()
    findings = Finding.objects.all().order_by("id")

    if user.is_superuser:
        return findings

    if user_has_global_permission(user, permission):
        return findings

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
    return findings.filter(
        Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_groups)),
    )


register_auth_filter("finding.get_authorized_findings", _get_authorized_findings)


def _get_authorized_findings_for_queryset(permission, queryset, user=None):
    """Filters a provided queryset for authorization. Not cached due to dynamic queryset parameter."""
    if user is None:
        user = get_current_user()
    if user is None:
        return Finding.objects.none()
    findings = Finding.objects.all().order_by("id") if queryset is None else queryset

    if user.is_superuser:
        return findings

    if user_has_global_permission(user, permission):
        return findings

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
    return findings.filter(
        Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_groups)),
    )


register_auth_filter("finding.get_authorized_findings_for_queryset", _get_authorized_findings_for_queryset)


def _get_authorized_stub_findings(permission):
    user = get_current_user()

    if user is None:
        return Stub_Finding.objects.none()

    if user.is_superuser:
        return Stub_Finding.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Stub_Finding.objects.all().order_by("id")

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
    return Stub_Finding.objects.filter(
        Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_groups)),
    ).order_by("id")


register_auth_filter("finding.get_authorized_stub_findings", _get_authorized_stub_findings)


def _get_authorized_vulnerability_ids(permission, user=None):
    """Cached - returns all vulnerability IDs the user is authorized to see."""
    if user is None:
        user = get_current_user()

    if user is None:
        return Vulnerability_Id.objects.none()

    vulnerability_ids = Vulnerability_Id.objects.all()

    if user.is_superuser:
        return vulnerability_ids

    if user_has_global_permission(user, permission):
        return vulnerability_ids

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
    return vulnerability_ids.filter(
        Q(finding__test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(finding__test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(finding__test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(finding__test__engagement__product_id__in=Subquery(authorized_product_groups)),
    )


register_auth_filter("finding.get_authorized_vulnerability_ids", _get_authorized_vulnerability_ids)


def _get_authorized_vulnerability_ids_for_queryset(permission, queryset, user=None):
    """Filters a provided queryset for authorization. Not cached due to dynamic queryset parameter."""
    if user is None:
        user = get_current_user()

    if user is None:
        return Vulnerability_Id.objects.none()

    if user.is_superuser:
        return queryset

    if user_has_global_permission(user, permission):
        return queryset

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
    return queryset.filter(
        Q(finding__test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(finding__test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(finding__test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(finding__test__engagement__product_id__in=Subquery(authorized_product_groups)),
    )


register_auth_filter("finding.get_authorized_vulnerability_ids_for_queryset", _get_authorized_vulnerability_ids_for_queryset)


# ============================================================================
# Endpoint queries
# ============================================================================

def _get_authorized_endpoints(permission, user=None):
    """Cached - returns all endpoints the user is authorized to see."""
    if user is None:
        user = get_current_user()

    if user is None:
        return Endpoint.objects.none()

    endpoints = Endpoint.objects.all().order_by("id")

    if user.is_superuser:
        return endpoints

    if user_has_global_permission(user, permission):
        return endpoints

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
    return endpoints.filter(
        Q(product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(product_id__in=Subquery(authorized_product_roles))
        | Q(product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(product_id__in=Subquery(authorized_product_groups)),
    )


register_auth_filter("endpoint.get_authorized_endpoints", _get_authorized_endpoints)


def _get_authorized_endpoints_for_queryset(permission, queryset, user=None):
    """Filters a provided queryset for authorization. Not cached due to dynamic queryset parameter."""
    if user is None:
        user = get_current_user()

    if user is None:
        return Endpoint.objects.none()

    if user.is_superuser:
        return queryset

    if user_has_global_permission(user, permission):
        return queryset

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
    return queryset.filter(
        Q(product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(product_id__in=Subquery(authorized_product_roles))
        | Q(product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(product_id__in=Subquery(authorized_product_groups)),
    )


register_auth_filter("endpoint.get_authorized_endpoints_for_queryset", _get_authorized_endpoints_for_queryset)


def _get_authorized_endpoint_status(permission, user=None):
    """Cached - returns all endpoint statuses the user is authorized to see."""
    if user is None:
        user = get_current_user()

    if user is None:
        return Endpoint_Status.objects.none()

    endpoint_status = Endpoint_Status.objects.all().order_by("id")

    if user.is_superuser:
        return endpoint_status

    if user_has_global_permission(user, permission):
        return endpoint_status

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
    return endpoint_status.filter(
        Q(endpoint__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(endpoint__product_id__in=Subquery(authorized_product_roles))
        | Q(endpoint__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(endpoint__product_id__in=Subquery(authorized_product_groups)),
    )


register_auth_filter("endpoint.get_authorized_endpoint_status", _get_authorized_endpoint_status)


def _get_authorized_endpoint_status_for_queryset(permission, queryset, user=None):
    """Filters a provided queryset for authorization. Not cached due to dynamic queryset parameter."""
    if user is None:
        user = get_current_user()

    if user is None:
        return Endpoint_Status.objects.none()

    if user.is_superuser:
        return queryset

    if user_has_global_permission(user, permission):
        return queryset

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
    return queryset.filter(
        Q(endpoint__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(endpoint__product_id__in=Subquery(authorized_product_roles))
        | Q(endpoint__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(endpoint__product_id__in=Subquery(authorized_product_groups)),
    )


register_auth_filter("endpoint.get_authorized_endpoint_status_for_queryset", _get_authorized_endpoint_status_for_queryset)


# ============================================================================
# User queries
# ============================================================================

def _get_authorized_users_for_product_type(users, product_type, permission):
    roles = get_roles_for_permission(permission)

    # Get user IDs via subqueries instead of materializing into Python lists
    product_type_member_users = Product_Type_Member.objects.filter(
        product_type=product_type, role__in=roles,
    ).values("user_id")

    # Get group IDs that have access to this product type
    product_type_group_ids = Product_Type_Group.objects.filter(
        product_type=product_type, role__in=roles,
    ).values("group_id")

    global_role_group_ids = Global_Role.objects.filter(
        role__in=roles, group__isnull=False,
    ).values("group_id")

    # Get users from those groups
    group_member_users = Dojo_Group_Member.objects.filter(
        Q(group_id__in=Subquery(product_type_group_ids))
        | Q(group_id__in=Subquery(global_role_group_ids)),
    ).values("user_id")

    return users.filter(
        Q(id__in=Subquery(product_type_member_users))
        | Q(id__in=Subquery(group_member_users))
        | Q(global_role__role__in=roles)
        | Q(is_superuser=True),
    )


register_auth_filter("user.get_authorized_users_for_product_type", _get_authorized_users_for_product_type)


def _get_authorized_users_for_product_and_product_type(users, product, permission):
    if users is None:
        users = Dojo_User.objects.filter(is_active=True)

    roles = get_roles_for_permission(permission)

    # Get user IDs via subqueries instead of materializing into Python lists
    product_member_users = Product_Member.objects.filter(
        product=product, role__in=roles,
    ).values("user_id")

    product_type_member_users = Product_Type_Member.objects.filter(
        product_type=product.prod_type, role__in=roles,
    ).values("user_id")

    # Get group IDs that have access to this product or product type
    product_group_ids = Product_Group.objects.filter(
        product=product, role__in=roles,
    ).values("group_id")

    product_type_group_ids = Product_Type_Group.objects.filter(
        product_type=product.prod_type, role__in=roles,
    ).values("group_id")

    global_role_group_ids = Global_Role.objects.filter(
        role__in=roles, group__isnull=False,
    ).values("group_id")

    # Get users from those groups
    group_member_users = Dojo_Group_Member.objects.filter(
        Q(group_id__in=Subquery(product_group_ids))
        | Q(group_id__in=Subquery(product_type_group_ids))
        | Q(group_id__in=Subquery(global_role_group_ids)),
    ).values("user_id")

    return users.filter(
        Q(id__in=Subquery(product_member_users))
        | Q(id__in=Subquery(product_type_member_users))
        | Q(id__in=Subquery(group_member_users))
        | Q(global_role__role__in=roles)
        | Q(is_superuser=True),
    )


register_auth_filter("user.get_authorized_users_for_product_and_product_type", _get_authorized_users_for_product_and_product_type)


def _get_authorized_users(permission, user=None):
    from dojo.product.queries import get_authorized_products  # noqa: PLC0415
    from dojo.product_type.queries import get_authorized_product_types  # noqa: PLC0415

    if user is None:
        user = get_current_user()

    if user is None:
        return Dojo_User.objects.none()

    if user.is_anonymous:
        return Dojo_User.objects.none()

    users = Dojo_User.objects.all().order_by("first_name", "last_name", "username")

    if user.is_superuser or user_has_global_permission(user, permission):
        return users

    authorized_products = get_authorized_products(permission).values("id")
    authorized_product_types = get_authorized_product_types(permission).values("id")

    roles = get_roles_for_permission(permission)

    # Get user IDs via subqueries instead of materializing into Python lists
    product_member_users = Product_Member.objects.filter(
        product_id__in=Subquery(authorized_products), role__in=roles,
    ).values("user_id")

    product_type_member_users = Product_Type_Member.objects.filter(
        product_type_id__in=Subquery(authorized_product_types), role__in=roles,
    ).values("user_id")

    # Get group IDs that have access to authorized products/product types
    product_group_ids = Product_Group.objects.filter(
        product_id__in=Subquery(authorized_products), role__in=roles,
    ).values("group_id")

    product_type_group_ids = Product_Type_Group.objects.filter(
        product_type_id__in=Subquery(authorized_product_types), role__in=roles,
    ).values("group_id")

    # Get users from those groups
    group_member_users = Dojo_Group_Member.objects.filter(
        Q(group_id__in=Subquery(product_group_ids))
        | Q(group_id__in=Subquery(product_type_group_ids)),
    ).values("user_id")

    return users.filter(
        Q(id__in=Subquery(product_member_users))
        | Q(id__in=Subquery(product_type_member_users))
        | Q(id__in=Subquery(group_member_users))
        | Q(global_role__role__in=roles)
        | Q(is_superuser=True),
    )


register_auth_filter("user.get_authorized_users", _get_authorized_users)


# ============================================================================
# Group queries
# ============================================================================

def _get_authorized_groups(permission):
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


register_auth_filter("group.get_authorized_groups", _get_authorized_groups)


def _get_authorized_group_members(permission):
    from dojo.group.queries import get_authorized_groups  # noqa: PLC0415

    user = get_current_user()

    if user is None:
        return Dojo_Group_Member.objects.none()

    if user.is_superuser:
        return Dojo_Group_Member.objects.all().order_by("id").select_related("role")

    groups = get_authorized_groups(permission)
    return Dojo_Group_Member.objects.filter(group__in=groups).order_by("id").select_related("role")


register_auth_filter("group.get_authorized_group_members", _get_authorized_group_members)


def _get_authorized_group_members_for_user(user):
    from dojo.group.queries import get_authorized_groups  # noqa: PLC0415

    groups = get_authorized_groups(Permissions.Group_View)
    return Dojo_Group_Member.objects.filter(user=user, group__in=groups).order_by("group__name").select_related("role", "group")


register_auth_filter("group.get_authorized_group_members_for_user", _get_authorized_group_members_for_user)


# ============================================================================
# Location queries
# ============================================================================

def _get_authorized_locations(permission, queryset=None, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return Location.objects.none()

    locations = Location.objects.all().order_by("id") if queryset is None else queryset

    if user.is_superuser:
        return locations

    if user_has_global_permission(user, permission):
        return locations

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef("products__product__prod_type_id"),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("products__product_id"),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("products__product__prod_type_id"),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("products__product_id"),
        group__users=user,
        role__in=roles)
    locations = locations.annotate(
        product__prod_type__member=Exists(authorized_product_type_roles),
        product__member=Exists(authorized_product_roles),
        product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        product__authorized_group=Exists(authorized_product_groups))
    return locations.filter(
        Q(product__prod_type__member=True) | Q(product__member=True)
        | Q(product__prod_type__authorized_group=True) | Q(product__authorized_group=True))


register_auth_filter("location.get_authorized_locations", _get_authorized_locations)


def _get_authorized_location_finding_reference(permission, queryset=None, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return LocationFindingReference.objects.none()

    location_finding_reference = LocationFindingReference.objects.all().order_by("id") if queryset is None else queryset

    if user.is_superuser:
        return location_finding_reference

    if user_has_global_permission(user, permission):
        return location_finding_reference

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef("location__products__product__prod_type_id"),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("location__products__product_id"),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("location__products__product__prod_type_id"),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("location__products__product_id"),
        group__users=user,
        role__in=roles)
    location_finding_reference = location_finding_reference.annotate(
        location__product__prod_type__member=Exists(authorized_product_type_roles),
        location__product__member=Exists(authorized_product_roles),
        location__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        location__product__authorized_group=Exists(authorized_product_groups))
    return location_finding_reference.filter(
        Q(location__product__prod_type__member=True) | Q(location__product__member=True)
        | Q(location__product__prod_type__authorized_group=True) | Q(location__product__authorized_group=True))


register_auth_filter("location.get_authorized_location_finding_reference", _get_authorized_location_finding_reference)


def _get_authorized_location_product_reference(permission, queryset=None, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return LocationProductReference.objects.none()

    location_product_reference = LocationProductReference.objects.all().order_by("id") if queryset is None else queryset

    if user.is_superuser:
        return location_product_reference

    if user_has_global_permission(user, permission):
        return location_product_reference

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef("product__prod_type_id"),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("product_id"),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("product__prod_type_id"),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("product_id"),
        group__users=user,
        role__in=roles)
    location_product_reference = location_product_reference.annotate(
        location__product__prod_type__member=Exists(authorized_product_type_roles),
        location__product__member=Exists(authorized_product_roles),
        location__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        location__product__authorized_group=Exists(authorized_product_groups))
    return location_product_reference.filter(
        Q(location__product__prod_type__member=True) | Q(location__product__member=True)
        | Q(location__product__prod_type__authorized_group=True) | Q(location__product__authorized_group=True))


register_auth_filter("location.get_authorized_location_product_reference", _get_authorized_location_product_reference)


# ============================================================================
# Test queries
# ============================================================================

def _get_authorized_tests(permission, product=None):
    user = get_current_user()

    if user is None:
        return Test.objects.none()

    tests = Test.objects.all().order_by("id")
    if product:
        tests = tests.filter(engagement__product=product)

    if user.is_superuser:
        return tests

    if user_has_global_permission(user, permission):
        return Test.objects.all().order_by("id")

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
    return tests.filter(
        Q(engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(engagement__product_id__in=Subquery(authorized_product_groups)),
    )


register_auth_filter("test.get_authorized_tests", _get_authorized_tests)


def _get_authorized_test_imports(permission):
    user = get_current_user()

    if user is None:
        return Test_Import.objects.none()

    if user.is_superuser:
        return Test_Import.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Test_Import.objects.all().order_by("id")

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
    return Test_Import.objects.filter(
        Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_groups)),
    ).order_by("id")


register_auth_filter("test.get_authorized_test_imports", _get_authorized_test_imports)


# ============================================================================
# Jira Link queries
# ============================================================================

def _get_authorized_jira_projects(permission, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return JIRA_Project.objects.none()

    jira_projects = JIRA_Project.objects.all().order_by("id")

    if user.is_superuser:
        return jira_projects

    if user_has_global_permission(user, permission):
        return jira_projects

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
    # JIRA projects can be attached via engagement or product path
    return jira_projects.filter(
        # Engagement path
        Q(engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(engagement__product_id__in=Subquery(authorized_product_groups))
        # Product path
        | Q(product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(product_id__in=Subquery(authorized_product_roles))
        | Q(product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(product_id__in=Subquery(authorized_product_groups)),
    )


register_auth_filter("jira_link.get_authorized_jira_projects", _get_authorized_jira_projects)


def _get_authorized_jira_issues(permission):
    user = get_current_user()

    if user is None:
        return JIRA_Issue.objects.none()

    jira_issues = JIRA_Issue.objects.all().order_by("id")

    if user.is_superuser:
        return jira_issues

    if user_has_global_permission(user, permission):
        return jira_issues

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
    # JIRA issues can be attached via engagement, finding_group, or finding path
    return jira_issues.filter(
        # Engagement path
        Q(engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(engagement__product_id__in=Subquery(authorized_product_groups))
        # Finding group path
        | Q(finding_group__test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(finding_group__test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(finding_group__test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(finding_group__test__engagement__product_id__in=Subquery(authorized_product_groups))
        # Finding path
        | Q(finding__test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(finding__test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(finding__test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(finding__test__engagement__product_id__in=Subquery(authorized_product_groups)),
    )


register_auth_filter("jira_link.get_authorized_jira_issues", _get_authorized_jira_issues)


# ============================================================================
# Engagement queries
# ============================================================================

def _get_authorized_engagements(permission):
    user = get_current_user()

    if user is None:
        return Engagement.objects.none()

    if user.is_superuser:
        return Engagement.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Engagement.objects.all().order_by("id")

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
    return Engagement.objects.filter(
        Q(product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(product_id__in=Subquery(authorized_product_roles))
        | Q(product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(product_id__in=Subquery(authorized_product_groups)),
    ).order_by("id")


register_auth_filter("engagement.get_authorized_engagements", _get_authorized_engagements)


# ============================================================================
# Risk Acceptance queries
# ============================================================================

def _get_authorized_risk_acceptances(permission):
    user = get_current_user()

    if user is None:
        return Risk_Acceptance.objects.none()

    if user.is_superuser:
        return Risk_Acceptance.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Risk_Acceptance.objects.all().order_by("id")

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
    return Risk_Acceptance.objects.filter(
        Q(engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(engagement__product_id__in=Subquery(authorized_product_groups)),
    ).order_by("id")


register_auth_filter("risk_acceptance.get_authorized_risk_acceptances", _get_authorized_risk_acceptances)


# ============================================================================
# Finding Group queries
# ============================================================================

def _get_authorized_finding_groups(permission, user=None):
    """Cached - returns all finding groups the user is authorized to see."""
    if user is None:
        user = get_current_user()

    if user is None:
        return Finding_Group.objects.none()

    finding_groups = Finding_Group.objects.all()

    if user.is_superuser:
        return finding_groups

    if user_has_global_permission(user, permission):
        return finding_groups

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
    return finding_groups.filter(
        Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_groups)),
    )


register_auth_filter("finding_group.get_authorized_finding_groups", _get_authorized_finding_groups)


def _get_authorized_finding_groups_for_queryset(permission, queryset, user=None):
    """Filters a provided queryset for authorization. Not cached due to dynamic queryset parameter."""
    if user is None:
        user = get_current_user()

    if user is None:
        return Finding_Group.objects.none()

    if user.is_superuser:
        return queryset

    if user_has_global_permission(user, permission):
        return queryset

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
    return queryset.filter(
        Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_groups)),
    )


register_auth_filter("finding_group.get_authorized_finding_groups_for_queryset", _get_authorized_finding_groups_for_queryset)


# ============================================================================
# Tool Product queries
# ============================================================================

def _get_authorized_tool_product_settings(permission):
    user = get_current_user()

    if user is None:
        return Tool_Product_Settings.objects.none()

    if user.is_superuser:
        return Tool_Product_Settings.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Tool_Product_Settings.objects.all().order_by("id")

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
    return Tool_Product_Settings.objects.filter(
        Q(product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(product_id__in=Subquery(authorized_product_roles))
        | Q(product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(product_id__in=Subquery(authorized_product_groups)),
    ).order_by("id")


register_auth_filter("tool_product.get_authorized_tool_product_settings", _get_authorized_tool_product_settings)


# ============================================================================
# Cred queries
# ============================================================================

def _get_authorized_cred_mappings(permission):
    """Cached - returns all cred mappings the user is authorized to see."""
    user = get_current_user()

    if user is None:
        return Cred_Mapping.objects.none()

    cred_mappings = Cred_Mapping.objects.all().order_by("id")

    if user.is_superuser:
        return cred_mappings

    if user_has_global_permission(user, permission):
        return cred_mappings

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
    return cred_mappings.filter(
        Q(product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(product_id__in=Subquery(authorized_product_roles))
        | Q(product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(product_id__in=Subquery(authorized_product_groups)),
    )


register_auth_filter("cred.get_authorized_cred_mappings", _get_authorized_cred_mappings)


def _get_authorized_cred_mappings_for_queryset(permission, queryset):
    """Filters a provided queryset for authorization. Not cached due to dynamic queryset parameter."""
    user = get_current_user()

    if user is None:
        return Cred_Mapping.objects.none()

    if user.is_superuser:
        return queryset

    if user_has_global_permission(user, permission):
        return queryset

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
    return queryset.filter(
        Q(product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(product_id__in=Subquery(authorized_product_roles))
        | Q(product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(product_id__in=Subquery(authorized_product_groups)),
    )


register_auth_filter("cred.get_authorized_cred_mappings_for_queryset", _get_authorized_cred_mappings_for_queryset)
