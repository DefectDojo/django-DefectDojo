from crum import get_current_user
from django.db.models import Exists, OuterRef, Q
from dojo.models import Finding, Product_Member, Product_Type_Member, Stub_Finding, \
    Product_Group, Product_Type_Group, Vulnerability_Id
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission


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

    if user_has_global_permission(user, permission):
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
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('test__engagement__product__prod_type_id'),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('test__engagement__product_id'),
        group__users=user,
        role__in=roles)
    findings = findings.annotate(
        test__engagement__product__prod_type__member=Exists(authorized_product_type_roles),
        test__engagement__product__member=Exists(authorized_product_roles),
        test__engagement__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        test__engagement__product__authorized_group=Exists(authorized_product_groups))
    findings = findings.filter(
        Q(test__engagement__product__prod_type__member=True) |
        Q(test__engagement__product__member=True) |
        Q(test__engagement__product__prod_type__authorized_group=True) |
        Q(test__engagement__product__authorized_group=True))

    return findings


def get_authorized_stub_findings(permission):
    user = get_current_user()

    if user is None:
        return Stub_Finding.objects.none()

    if user.is_superuser:
        return Stub_Finding.objects.all()

    if user_has_global_permission(user, permission):
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
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('test__engagement__product__prod_type_id'),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('test__engagement__product_id'),
        group__users=user,
        role__in=roles)
    findings = Stub_Finding.objects.annotate(
        test__engagement__product__prod_type__member=Exists(authorized_product_type_roles),
        test__engagement__product__member=Exists(authorized_product_roles),
        test__engagement__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        test__engagement__product__authorized_group=Exists(authorized_product_groups))
    findings = findings.filter(
        Q(test__engagement__product__prod_type__member=True) |
        Q(test__engagement__product__member=True) |
        Q(test__engagement__product__prod_type__authorized_group=True) |
        Q(test__engagement__product__authorized_group=True))

    return findings


def get_authorized_vulnerability_ids(permission, queryset=None, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return Vulnerability_Id.objects.none()

    if queryset is None:
        vulnerability_ids = Vulnerability_Id.objects.all()
    else:
        vulnerability_ids = queryset

    if user.is_superuser:
        return vulnerability_ids

    if user_has_global_permission(user, permission):
        return vulnerability_ids

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef('finding__test__engagement__product__prod_type_id'),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef('finding__test__engagement__product_id'),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('finding__test__engagement__product__prod_type_id'),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('finding__test__engagement__product_id'),
        group__users=user,
        role__in=roles)
    vulnerability_ids = vulnerability_ids.annotate(
        finding__test__engagement__product__prod_type__member=Exists(authorized_product_type_roles),
        finding__test__engagement__product__member=Exists(authorized_product_roles),
        finding__test__engagement__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        finding__test__engagement__product__authorized_group=Exists(authorized_product_groups))
    vulnerability_ids = vulnerability_ids.filter(
        Q(finding__test__engagement__product__prod_type__member=True) |
        Q(finding__test__engagement__product__member=True) |
        Q(finding__test__engagement__product__prod_type__authorized_group=True) |
        Q(finding__test__engagement__product__authorized_group=True))

    return vulnerability_ids
