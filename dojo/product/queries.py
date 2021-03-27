from crum import get_current_user
from django.conf import settings
from django.db.models import Exists, OuterRef, Q
from dojo.models import Product, Product_Member, Product_Type_Member, App_Analysis
from dojo.authorization.authorization import get_roles_for_permission, user_has_permission


def get_authorized_products(permission):
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


def get_authorized_product_members(product, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product, permission):
        return Product_Member.objects.filter(product=product).order_by('user__first_name', 'user__last_name')
    else:
        return None


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
