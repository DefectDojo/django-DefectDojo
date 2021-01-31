from crum import get_current_user
from django.conf import settings
from django.db.models import Exists, OuterRef, Q
from dojo.models import Product, Product_Member, Product_Type_Member
from dojo.authorization.authorization import get_roles_for_permission


def get_authorized_products(permission):
    user = get_current_user()
    if user.is_superuser:
        return Product.objects.all().order_by('name')

    if settings.FEATURE_NEW_AUTHORIZATION:
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
