from crum import get_current_user
from django.conf import settings
from django.db.models import Exists, OuterRef, Q
from dojo.models import Engagement, Product_Member, Product_Type_Member
from dojo.authorization.authorization import get_roles_for_permission


def get_authorized_engagements(permission):
    user = get_current_user()

    if user is None:
        return Engagement.objects.none()

    if user.is_superuser:
        return Engagement.objects.all()

    if settings.FEATURE_AUTHORIZATION_V2:
        if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
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
        engagements = Engagement.objects.annotate(
            product__prod_type__member=Exists(authorized_product_type_roles),
            product__member=Exists(authorized_product_roles))
        engagements = engagements.filter(
            Q(product__prod_type__member=True) |
            Q(product__member=True))
    else:
        if user.is_staff:
            engagements = Engagement.objects.all()
        else:
            engagements = Engagement.objects.filter(
                Q(product__authorized_users__in=[user]) |
                Q(product__prod_type__authorized_users__in=[user]))
    return engagements
