from crum import get_current_user
from django.db.models import Exists, OuterRef, Q
from dojo.models import Finding_Group, Product_Member, Product_Type_Member, \
    Product_Group, Product_Type_Group
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission


def get_authorized_finding_groups(permission, queryset=None, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return Finding_Group.objects.none()

    if queryset is None:
        finding_groups = Finding_Group.objects.all()
    else:
        finding_groups = queryset

    if user.is_superuser:
        return finding_groups

    if user_has_global_permission(user, permission):
        return finding_groups

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef('test__engagement__product__prod_type_id'),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef('test__engagement__product_id'),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('test__engagement__product__prod_type_id'),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('test__engagement__product_id'),
        group__users=user,
        role__in=roles)
    finding_groups = finding_groups.annotate(
        test__engagement__product__prod_type__member=Exists(authorized_product_type_roles),
        test__engagement__product__member=Exists(authorized_product_roles),
        test__engagement__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        test__engagement__product__authorized_group=Exists(authorized_product_groups))
    finding_groups = finding_groups.filter(
        Q(test__engagement__product__prod_type__member=True) |
        Q(test__engagement__product__member=True) |
        Q(test__engagement__product__prod_type__authorized_group=True) |
        Q(test__engagement__product__authorized_group=True))

    return finding_groups
