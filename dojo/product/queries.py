from crum import get_current_user
from django.conf import settings
from django.db.models import Exists, OuterRef, Q
from dojo.models import Product, Product_Member, Product_Type_Member, App_Analysis, \
    DojoMeta, Product_Group, Product_Type_Group
from dojo.authorization.authorization import get_roles_for_permission, user_has_permission, \
    role_has_permission, get_groups
from dojo.group.queries import get_authorized_groups
from dojo.authorization.roles_permissions import Permissions


def get_authorized_products(permission, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return Product.objects.none()

    if user.is_superuser:
        return Product.objects.all().order_by('name')

    if settings.FEATURE_AUTHORIZATION_V2:
        if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
            return Product.objects.all().order_by('name')

        if hasattr(user, 'global_role') and user.global_role.role is not None and role_has_permission(user.global_role.role.id, permission):
            return Product.objects.all().order_by('name')

        for group in get_groups(user):
            if hasattr(group, 'global_role') and group.global_role.role is not None and role_has_permission(group.global_role.role.id, permission):
                return Product.objects.all().order_by('name')

        roles = get_roles_for_permission(permission)
        authorized_product_type_roles = Product_Type_Member.objects.filter(
            product_type=OuterRef('prod_type_id'),
            user=user,
            role__in=roles)
        authorized_product_roles = Product_Member.objects.filter(
            product=OuterRef('pk'),
            user=user,
            role__in=roles)
        authorized_product_type_groups = Product_Type_Group.objects.filter(
            product_type=OuterRef('prod_type_id'),
            group__users=user,
            role__in=roles)
        authorized_product_groups = Product_Group.objects.filter(
            product=OuterRef('pk'),
            group__users=user,
            role__in=roles)
        products = Product.objects.annotate(
            prod_type__member=Exists(authorized_product_type_roles),
            member=Exists(authorized_product_roles),
            prod_type__authorized_group=Exists(authorized_product_type_groups),
            authorized_group=Exists(authorized_product_groups)).order_by('name')
        products = products.filter(
            Q(prod_type__member=True) | Q(member=True) |
            Q(prod_type__authorized_group=True) | Q(authorized_group=True))
    else:
        if user.is_staff:
            products = Product.objects.all().order_by('name')
        else:
            products = Product.objects.filter(
                Q(authorized_users__in=[user]) |
                Q(prod_type__authorized_users__in=[user])).order_by('name')
    return products


def get_authorized_members_for_product(product, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product, permission):
        return Product_Member.objects.filter(product=product).order_by('user__first_name', 'user__last_name').select_related('role')
    else:
        return None


def get_authorized_groups_for_product(product, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product, permission):
        authorized_groups = get_authorized_groups(Permissions.Group_View)
        return Product_Group.objects.filter(product=product, group__in=authorized_groups).order_by('group__name').select_related('role')
    else:
        return None


def get_authorized_product_members(permission):
    user = get_current_user()

    if user is None:
        return Product_Member.objects.none()

    if user.is_superuser:
        return Product_Member.objects.all().select_related('role')

    if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
        return Product_Member.objects.all().select_related('role')

    if hasattr(user, 'global_role') and user.global_role.role is not None and role_has_permission(user.global_role.role.id, permission):
        return Product_Member.objects.all().select_related('role')

    products = get_authorized_products(permission)
    return Product_Member.objects.filter(product__in=products).select_related('role')


def get_authorized_product_members_for_user(user, permission):
    request_user = get_current_user()

    if request_user is None:
        return Product_Member.objects.none()

    if request_user.is_superuser:
        return Product_Member.objects.filter(user=user).select_related('role', 'product')

    if request_user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
        return Product_Member.objects.filter(user=user).select_related('role', 'product')

    if hasattr(request_user, 'global_role') and request_user.global_role.role is not None and role_has_permission(request_user.global_role.role.id, permission):
        return Product_Member.objects.filter(user=user).select_related('role', 'product')

    products = get_authorized_products(permission)
    return Product_Member.objects.filter(user=user, product__in=products).select_related('role', 'product')


def get_authorized_product_groups(permission):
    user = get_current_user()

    if user is None:
        return Product_Group.objects.none()

    if user.is_superuser:
        return Product_Group.objects.all().select_related('role')

    if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
        return Product_Group.objects.all()

    products = get_authorized_products(permission)
    return Product_Group.objects.filter(product__in=products).select_related('role')


def get_authorized_app_analysis(permission):
    user = get_current_user()

    if user is None:
        return App_Analysis.objects.none()

    if user.is_superuser:
        return App_Analysis.objects.all().order_by('name')

    if settings.FEATURE_AUTHORIZATION_V2:
        if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
            return App_Analysis.objects.all().order_by('name')

        if hasattr(user, 'global_role') and user.global_role.role is not None and role_has_permission(user.global_role.role.id, permission):
            return App_Analysis.objects.all().order_by('name')

        for group in get_groups(user):
            if hasattr(group, 'global_role') and group.global_role.role is not None and role_has_permission(group.global_role.role.id, permission):
                return App_Analysis.objects.all().order_by('name')

        roles = get_roles_for_permission(permission)
        authorized_product_type_roles = Product_Type_Member.objects.filter(
            product_type=OuterRef('product__prod_type_id'),
            user=user,
            role__in=roles)
        authorized_product_roles = Product_Member.objects.filter(
            product=OuterRef('product_id'),
            user=user,
            role__in=roles)
        authorized_product_type_groups = Product_Type_Group.objects.filter(
            product_type=OuterRef('product__prod_type_id'),
            group__users=user,
            role__in=roles)
        authorized_product_groups = Product_Group.objects.filter(
            product=OuterRef('product_id'),
            group__users=user,
            role__in=roles)
        app_analysis = App_Analysis.objects.annotate(
            product__prod_type__member=Exists(authorized_product_type_roles),
            product__member=Exists(authorized_product_roles),
            product__prod_type__authorized_group=Exists(authorized_product_type_groups),
            product__authorized_group=Exists(authorized_product_groups)).order_by('name')
        app_analysis = app_analysis.filter(
            Q(product__prod_type__member=True) | Q(product__member=True) |
            Q(product__prod_type__authorized_group=True) | Q(product__authorized_group=True))
    else:
        if user.is_staff:
            app_analysis = App_Analysis.objects.all().order_by('name')
        else:
            app_analysis = App_Analysis.objects.filter(
                Q(product__authorized_users__in=[user]) |
                Q(product__prod_type__authorized_users__in=[user])).order_by('name')
    return app_analysis


def get_authorized_dojo_meta(permission):
    user = get_current_user()

    if user is None:
        return DojoMeta.objects.none()

    if user.is_superuser:
        return DojoMeta.objects.all().order_by('name')

    if settings.FEATURE_AUTHORIZATION_V2:
        if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
            return DojoMeta.objects.all().order_by('name')

        if hasattr(user, 'global_role') and user.global_role.role is not None and role_has_permission(user.global_role.role.id, permission):
            return DojoMeta.objects.all().order_by('name')

        for group in get_groups(user):
            if hasattr(group, 'global_role') and group.global_role.role is not None and role_has_permission(group.global_role.role.id, permission):
                return DojoMeta.objects.all().order_by('name')

        roles = get_roles_for_permission(permission)
        product_authorized_product_type_roles = Product_Type_Member.objects.filter(
            product_type=OuterRef('product__prod_type_id'),
            user=user,
            role__in=roles)
        product_authorized_product_roles = Product_Member.objects.filter(
            product=OuterRef('product_id'),
            user=user,
            role__in=roles)
        product_authorized_product_type_groups = Product_Type_Group.objects.filter(
            product_type=OuterRef('product__prod_type_id'),
            group__users=user,
            role__in=roles)
        product_authorized_product_groups = Product_Group.objects.filter(
            product=OuterRef('product_id'),
            group__users=user,
            role__in=roles)
        endpoint_authorized_product_type_roles = Product_Type_Member.objects.filter(
            product_type=OuterRef('endpoint__product__prod_type_id'),
            user=user,
            role__in=roles)
        endpoint_authorized_product_roles = Product_Member.objects.filter(
            product=OuterRef('endpoint__product_id'),
            user=user,
            role__in=roles)
        endpoint_authorized_product_type_groups = Product_Type_Group.objects.filter(
            product_type=OuterRef('endpoint__product__prod_type_id'),
            group__users=user,
            role__in=roles)
        endpoint_authorized_product_groups = Product_Group.objects.filter(
            product=OuterRef('endpoint__product_id'),
            group__users=user,
            role__in=roles)
        finding_authorized_product_type_roles = Product_Type_Member.objects.filter(
            product_type=OuterRef('finding__test__engagement__product__prod_type_id'),
            user=user,
            role__in=roles)
        finding_authorized_product_roles = Product_Member.objects.filter(
            product=OuterRef('finding__test__engagement__product_id'),
            user=user,
            role__in=roles)
        finding_authorized_product_type_groups = Product_Type_Group.objects.filter(
            product_type=OuterRef('finding__test__engagement__product__prod_type_id'),
            group__users=user,
            role__in=roles)
        finding_authorized_product_groups = Product_Group.objects.filter(
            product=OuterRef('finding__test__engagement__product_id'),
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
            finding__test__engagement__product__authorized_group=Exists(finding_authorized_product_groups)
        ).order_by('name')
        dojo_meta = dojo_meta.filter(
            Q(product__prod_type__member=True) |
            Q(product__member=True) |
            Q(product__prod_type__authorized_group=True) |
            Q(product__authorized_group=True) |
            Q(endpoint__product__prod_type__member=True) |
            Q(endpoint__product__member=True) |
            Q(endpoint__product__prod_type__authorized_group=True) |
            Q(endpoint__product__authorized_group=True) |
            Q(finding__test__engagement__product__prod_type__member=True) |
            Q(finding__test__engagement__product__member=True) |
            Q(finding__test__engagement__product__prod_type__authorized_group=True) |
            Q(finding__test__engagement__product__authorized_group=True))
    else:
        if user.is_staff:
            dojo_meta = DojoMeta.objects.all().order_by('name')
        else:
            dojo_meta = DojoMeta.objects.filter(
                Q(product__authorized_users__in=[user]) |
                Q(product__prod_type__authorized_users__in=[user]) |
                Q(endpoint__product__authorized_users__in=[user]) |
                Q(endpoint__product__prod_type__authorized_users__in=[user]) |
                Q(finding__test__engagement__product__authorized_users__in=[user]) |
                Q(finding__test__engagement__product__prod_type__authorized_users__in=[user])
            ).order_by('name')
    return dojo_meta
