from crum import get_current_user
from django.db.models import Exists, OuterRef, Q

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
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef("prod_type_id"),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("pk"),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("prod_type_id"),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("pk"),
        group__users=user,
        role__in=roles)
    products = Product.objects.annotate(
        prod_type__member=Exists(authorized_product_type_roles),
        member=Exists(authorized_product_roles),
        prod_type__authorized_group=Exists(authorized_product_type_groups),
        authorized_group=Exists(authorized_product_groups)).order_by("name")
    return products.filter(
        Q(prod_type__member=True) | Q(member=True)
        | Q(prod_type__authorized_group=True) | Q(authorized_group=True))


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


def get_authorized_app_analysis(permission):
    user = get_current_user()

    if user is None:
        return App_Analysis.objects.none()

    if user.is_superuser:
        return App_Analysis.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return App_Analysis.objects.all().order_by("id")

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
    app_analysis = App_Analysis.objects.annotate(
        product__prod_type__member=Exists(authorized_product_type_roles),
        product__member=Exists(authorized_product_roles),
        product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        product__authorized_group=Exists(authorized_product_groups)).order_by("id")
    return app_analysis.filter(
        Q(product__prod_type__member=True) | Q(product__member=True)
        | Q(product__prod_type__authorized_group=True) | Q(product__authorized_group=True))


def get_authorized_dojo_meta(permission):
    user = get_current_user()

    if user is None:
        return DojoMeta.objects.none()

    if user.is_superuser:
        return DojoMeta.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return DojoMeta.objects.all().order_by("id")

    roles = get_roles_for_permission(permission)
    product_authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef("product__prod_type_id"),
        user=user,
        role__in=roles)
    product_authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("product_id"),
        user=user,
        role__in=roles)
    product_authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("product__prod_type_id"),
        group__users=user,
        role__in=roles)
    product_authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("product_id"),
        group__users=user,
        role__in=roles)
    endpoint_authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef("endpoint__product__prod_type_id"),
        user=user,
        role__in=roles)
    endpoint_authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("endpoint__product_id"),
        user=user,
        role__in=roles)
    endpoint_authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("endpoint__product__prod_type_id"),
        group__users=user,
        role__in=roles)
    endpoint_authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("endpoint__product_id"),
        group__users=user,
        role__in=roles)
    finding_authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef("finding__test__engagement__product__prod_type_id"),
        user=user,
        role__in=roles)
    finding_authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("finding__test__engagement__product_id"),
        user=user,
        role__in=roles)
    finding_authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("finding__test__engagement__product__prod_type_id"),
        group__users=user,
        role__in=roles)
    finding_authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("finding__test__engagement__product_id"),
        group__users=user,
        role__in=roles)
    dojo_meta = DojoMeta.objects.annotate(
        product__prod_type__member=Exists(product_authorized_product_type_roles),
        product__member=Exists(product_authorized_product_roles),
        product__prod_type__authorized_group=Exists(product_authorized_product_type_groups),
        product__authorized_group=Exists(product_authorized_product_groups),
        endpoint__product__prod_type__member=Exists(endpoint_authorized_product_type_roles),
        endpoint__product__member=Exists(endpoint_authorized_product_roles),
        endpoint__product__prod_type__authorized_group=Exists(endpoint_authorized_product_type_groups),
        endpoint__product__authorized_group=Exists(endpoint_authorized_product_groups),
        finding__test__engagement__product__prod_type__member=Exists(finding_authorized_product_type_roles),
        finding__test__engagement__product__member=Exists(finding_authorized_product_roles),
        finding__test__engagement__product__prod_type__authorized_group=Exists(finding_authorized_product_type_groups),
        finding__test__engagement__product__authorized_group=Exists(finding_authorized_product_groups),
    ).order_by("id")
    return dojo_meta.filter(
        Q(product__prod_type__member=True)
        | Q(product__member=True)
        | Q(product__prod_type__authorized_group=True)
        | Q(product__authorized_group=True)
        | Q(endpoint__product__prod_type__member=True)
        | Q(endpoint__product__member=True)
        | Q(endpoint__product__prod_type__authorized_group=True)
        | Q(endpoint__product__authorized_group=True)
        | Q(finding__test__engagement__product__prod_type__member=True)
        | Q(finding__test__engagement__product__member=True)
        | Q(finding__test__engagement__product__prod_type__authorized_group=True)
        | Q(finding__test__engagement__product__authorized_group=True))


def get_authorized_languages(permission):
    user = get_current_user()

    if user is None:
        return Languages.objects.none()

    if user.is_superuser:
        return Languages.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Languages.objects.all().order_by("id")

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
    languages = Languages.objects.annotate(
        product__prod_type__member=Exists(authorized_product_type_roles),
        product__member=Exists(authorized_product_roles),
        product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        product__authorized_group=Exists(authorized_product_groups)).order_by("id")
    return languages.filter(
        Q(product__prod_type__member=True) | Q(product__member=True)
        | Q(product__prod_type__authorized_group=True) | Q(product__authorized_group=True))


def get_authorized_engagement_presets(permission):
    user = get_current_user()

    if user is None:
        return Engagement_Presets.objects.none()

    if user.is_superuser:
        return Engagement_Presets.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Engagement_Presets.objects.all().order_by("id")

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
    engagement_presets = Engagement_Presets.objects.annotate(
        product__prod_type__member=Exists(authorized_product_type_roles),
        product__member=Exists(authorized_product_roles),
        product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        product__authorized_group=Exists(authorized_product_groups)).order_by("id")
    return engagement_presets.filter(
        Q(product__prod_type__member=True) | Q(product__member=True)
        | Q(product__prod_type__authorized_group=True) | Q(product__authorized_group=True))


def get_authorized_product_api_scan_configurations(permission):
    user = get_current_user()

    if user is None:
        return Product_API_Scan_Configuration.objects.none()

    if user.is_superuser:
        return Product_API_Scan_Configuration.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Product_API_Scan_Configuration.objects.all().order_by("id")

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
    product_api_scan_configurations = Product_API_Scan_Configuration.objects.annotate(
        product__prod_type__member=Exists(authorized_product_type_roles),
        product__member=Exists(authorized_product_roles),
        product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        product__authorized_group=Exists(authorized_product_groups)).order_by("id")
    return product_api_scan_configurations.filter(
        Q(product__prod_type__member=True) | Q(product__member=True)
        | Q(product__prod_type__authorized_group=True) | Q(product__authorized_group=True))
