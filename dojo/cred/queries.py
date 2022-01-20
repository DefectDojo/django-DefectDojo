from crum import get_current_user
from django.db.models import Exists, OuterRef, Q
from dojo.models import Cred_Mapping, Product_Member, Product_Type_Member, \
    Product_Group, Product_Type_Group
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission


def get_authorized_cred_mappings(permission, queryset=None):
    user = get_current_user()

    if user is None:
        return Cred_Mapping.objects.none()

    if queryset is None:
        cred_mappings = Cred_Mapping.objects.all()
    else:
        cred_mappings = queryset

    if user.is_superuser:
        return cred_mappings

    if user_has_global_permission(user, permission):
        return cred_mappings

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
    cred_mappings = cred_mappings.annotate(
        product__prod_type__member=Exists(authorized_product_type_roles),
        product__member=Exists(authorized_product_roles),
        product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        product__authorized_group=Exists(authorized_product_groups))
    cred_mappings = cred_mappings.filter(
        Q(product__prod_type__member=True) | Q(product__member=True) |
        Q(product__prod_type__authorized_group=True) | Q(product__authorized_group=True))

    return cred_mappings
