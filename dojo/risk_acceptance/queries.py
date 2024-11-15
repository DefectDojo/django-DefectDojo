from crum import get_current_user
from django.db.models import Exists, OuterRef, Q

from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission
from dojo.models import Product_Group, Product_Member, Product_Type_Group, Product_Type_Member, Risk_Acceptance


def get_authorized_risk_acceptances(permission):
    user = get_current_user()

    if user is None:
        return Risk_Acceptance.objects.none()

    if user.is_superuser:
        return Risk_Acceptance.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Risk_Acceptance.objects.all().order_by("id")

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef("engagement__product__prod_type_id"),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("engagement__product_id"),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("engagement__product__prod_type_id"),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("engagement__product_id"),
        group__users=user,
        role__in=roles)
    risk_acceptances = Risk_Acceptance.objects.annotate(
        product__prod_type__member=Exists(authorized_product_type_roles),
        product__member=Exists(authorized_product_roles),
        product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        product__authorized_group=Exists(authorized_product_groups)).order_by("id")
    return risk_acceptances.filter(
        Q(product__prod_type__member=True) | Q(product__member=True)
        | Q(product__prod_type__authorized_group=True) | Q(product__authorized_group=True))
