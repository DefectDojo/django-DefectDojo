from crum import get_current_user
from django.conf import settings
from django.db.models import Exists, OuterRef, Q
from dojo.models import Finding, Product_Member, Product_Type_Member, Stub_Finding
from dojo.authorization.authorization import get_roles_for_permission


def get_authorized_findings(permission, queryset=None, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return Finding.objects.none()

    if queryset is None:
        findings = Finding.objects.all()
    else:
        findings = queryset

    if user.is_superuser:
        return findings

    if settings.FEATURE_AUTHORIZATION_V2:
        if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
            return findings

        roles = get_roles_for_permission(permission)
        authorized_product_type_roles = Product_Type_Member.objects.filter(
            product_type=OuterRef('test__engagement__product__prod_type_id'),
            user=user,
            role__in=roles)
        authorized_product_roles = Product_Member.objects.filter(
            product=OuterRef('test__engagement__product_id'),
            user=user,
            role__in=roles)
        findings = findings.annotate(
            test__engagement__product__prod_type__member=Exists(authorized_product_type_roles),
            test__engagement__product__member=Exists(authorized_product_roles))
        findings = findings.filter(
            Q(test__engagement__product__prod_type__member=True) |
            Q(test__engagement__product__member=True))
    else:
        if not user.is_staff:
            findings = findings.filter(
                Q(test__engagement__product__authorized_users__in=[user]) |
                Q(test__engagement__product__prod_type__authorized_users__in=[user]))
    return findings


def get_authorized_stub_findings(permission):
    user = get_current_user()

    if user is None:
        return Stub_Finding.objects.none()

    if user.is_superuser:
        return Stub_Finding.objects.all()

    if settings.FEATURE_AUTHORIZATION_V2:
        if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
            return Stub_Finding.objects.all()

        roles = get_roles_for_permission(permission)
        authorized_product_type_roles = Product_Type_Member.objects.filter(
            product_type=OuterRef('test__engagement__product__prod_type_id'),
            user=user,
            role__in=roles)
        authorized_product_roles = Product_Member.objects.filter(
            product=OuterRef('test__engagement__product_id'),
            user=user,
            role__in=roles)
        findings = Stub_Finding.objects.annotate(
            test__engagement__product__prod_type__member=Exists(authorized_product_type_roles),
            test__engagement__product__member=Exists(authorized_product_roles))
        findings = findings.filter(
            Q(test__engagement__product__prod_type__member=True) |
            Q(test__engagement__product__member=True))
    else:
        if user.is_staff:
            findings = Stub_Finding.objects.all()
        else:
            findings = Stub_Finding.objects.filter(
                Q(test__engagement__product__authorized_users__in=[user]) |
                Q(test__engagement__product__prod_type__authorized_users__in=[user]))
    return findings
