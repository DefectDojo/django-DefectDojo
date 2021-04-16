from crum import get_current_user
from django.conf import settings
from django.db.models import Exists, OuterRef, Q
from dojo.models import Product, Product_Member, Product_Type_Member, App_Analysis, DojoMeta
from dojo.authorization.authorization import get_roles_for_permission, user_has_permission


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

        roles = get_roles_for_permission(permission)
        authorized_product_type_roles = Product_Type_Member.objects.filter(
            product_type=OuterRef('prod_type_id'),
            user=user,
            role__in=roles)
        authorized_product_roles = Product_Member.objects.filter(
            product=OuterRef('pk'),
            user=user,
            role__in=roles)
        products = Product.objects.annotate(
            prod_type__member=Exists(authorized_product_type_roles),
            member=Exists(authorized_product_roles)).order_by('name')
        products = products.filter(
            Q(prod_type__member=True) |
            Q(member=True))
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
        return Product_Member.objects.filter(product=product).order_by('user__first_name', 'user__last_name')
    else:
        return None


def get_authorized_product_members(permission):
    user = get_current_user()

    if user is None:
        return Product_Member.objects.none()

    if user.is_superuser:
        return Product_Member.objects.all()

    if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
        return Product_Member.objects.all()

    products = get_authorized_products(permission)
    return Product_Member.objects.filter(product__in=products)


def get_authorized_product_members_for_user(user, permission):
    request_user = get_current_user()

    if request_user is None:
        return Product_Member.objects.none()

    if request_user.is_superuser:
        return Product_Member.objects.filter(user=user)

    if request_user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
        return Product_Member.objects.all(user=user)

    products = get_authorized_products(permission)
    return Product_Member.objects.filter(user=user, product__in=products)


def get_authorized_app_analysis(permission):
    user = get_current_user()

    if user is None:
        return App_Analysis.objects.none()

    if user.is_superuser:
        return App_Analysis.objects.all().order_by('name')

    if settings.FEATURE_AUTHORIZATION_V2:
        if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
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
        app_analysis = App_Analysis.objects.annotate(
            product__prod_type__member=Exists(authorized_product_type_roles),
            product__member=Exists(authorized_product_roles)).order_by('name')
        app_analysis = app_analysis.filter(
            Q(product__prod_type__member=True) |
            Q(product__member=True))
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

        roles = get_roles_for_permission(permission)
        product_authorized_product_type_roles = Product_Type_Member.objects.filter(
            product_type=OuterRef('product__prod_type_id'),
            user=user,
            role__in=roles)
        product_authorized_product_roles = Product_Member.objects.filter(
            product=OuterRef('product_id'),
            user=user,
            role__in=roles)
        endpoint_authorized_product_type_roles = Product_Type_Member.objects.filter(
            product_type=OuterRef('endpoint__product__prod_type_id'),
            user=user,
            role__in=roles)
        endpoint_authorized_product_roles = Product_Member.objects.filter(
            product=OuterRef('endpoint__product_id'),
            user=user,
            role__in=roles)
        finding_authorized_product_type_roles = Product_Type_Member.objects.filter(
            product_type=OuterRef('finding__test__engagement__product__prod_type_id'),
            user=user,
            role__in=roles)
        finding_authorized_product_roles = Product_Member.objects.filter(
            product=OuterRef('finding__test__engagement__product_id'),
            user=user,
            role__in=roles)
        dojo_meta = DojoMeta.objects.annotate(
            product__prod_type__member=Exists(product_authorized_product_type_roles),
            product__member=Exists(product_authorized_product_roles),
            endpoint_product__prod_type__member=Exists(endpoint_authorized_product_type_roles),
            endpoint_product__member=Exists(endpoint_authorized_product_roles),
            finding__test__engagement__product__prod_type__member=Exists(finding_authorized_product_type_roles),
            finding__test__engagement__product__member=Exists(finding_authorized_product_roles)
        ).order_by('name')
        dojo_meta = dojo_meta.filter(
            Q(product__prod_type__member=True) |
            Q(product__member=True) |
            Q(endpoint_product__prod_type__member=True) |
            Q(endpoint_product__member=True) |
            Q(finding__test__engagement__product__prod_type__member=True) |
            Q(finding__test__engagement__product__member=True))
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
