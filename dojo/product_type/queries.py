from crum import get_current_user
from django.db.models import Exists, OuterRef
from django.conf import settings
from dojo.models import Product_Type, Product_Type_Member
from dojo.authorization.authorization import get_roles_for_permission, user_has_permission


def get_authorized_product_types(permission):
    user = get_current_user()

    if user.is_superuser:
        return Product_Type.objects.all().order_by('name')

    if settings.FEATURE_NEW_AUTHORIZATION:
        roles = get_roles_for_permission(permission)
        authorized_roles = Product_Type_Member.objects.filter(product_type=OuterRef('pk'),
            user=user,
            role__in=roles)
        product_types = Product_Type.objects.annotate(member=Exists(authorized_roles)).order_by('name')
        product_types = product_types.filter(member=True)
    else:
        if user.is_staff:
            product_types = Product_Type.objects.all().order_by('name')
        else:
            product_types = Product_Type.objects.filter(authorized_users__in=[user]).order_by('name')
    return product_types


def get_authorized_members(product_type, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product_type, permission):
        return Product_Type_Member.objects.filter(product_type=product_type).order_by('user__first_name', 'user__last_name')
    else:
        return None
