from crum import get_current_user
from django.db.models import Exists, OuterRef, Q
from dojo.models import Engagement, Product_Member, Product_Type_Member, \
    Product_Group, Product_Type_Group
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission


def get_authorized_engagements(permission):
    user = get_current_user()

    if user is None:
        return Engagement.objects.none()

    if user.is_superuser:
        return Engagement.objects.all()

    if user_has_global_permission(user, permission):
        return Engagement.objects.all()

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
    engagements = Engagement.objects.annotate(
        product__prod_type__member=Exists(authorized_product_type_roles),
        product__member=Exists(authorized_product_roles),
        product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        product__authorized_group=Exists(authorized_product_groups))
    engagements = engagements.filter(
        Q(product__prod_type__member=True) | Q(product__member=True) |
        Q(product__prod_type__authorized_group=True) | Q(product__authorized_group=True))

    return engagements
