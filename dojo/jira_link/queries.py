from crum import get_current_user
from django.db.models import Exists, OuterRef, Q
from dojo.models import JIRA_Issue, JIRA_Project, Product_Member, Product_Type_Member, \
    Product_Group, Product_Type_Group
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission


def get_authorized_jira_projects(permission, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return JIRA_Project.objects.none()

    jira_projects = JIRA_Project.objects.all()

    if user.is_superuser:
        return jira_projects

    if user_has_global_permission(user, permission):
        return jira_projects

    roles = get_roles_for_permission(permission)
    engagement_authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef('engagement__product__prod_type_id'),
        user=user,
        role__in=roles)
    engagement_authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef('engagement__product_id'),
        user=user,
        role__in=roles)
    engagement_authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('engagement__product__prod_type_id'),
        group__users=user,
        role__in=roles)
    engagement_authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('engagement__product_id'),
        group__users=user,
        role__in=roles)
    product_authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef('product__prod_type_id'),
        user=user,
        role__in=roles)
    product_authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef('product_id'),
        user=user,
        role__in=roles)
    product_authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('product__prod_type_id'),
        group__users=user,
        role__in=roles)
    product_authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('product_id'),
        group__users=user,
        role__in=roles)
    jira_projects = jira_projects.annotate(
        engagement__product__prod_type__member=Exists(engagement_authorized_product_type_roles),
        engagement__product__member=Exists(engagement_authorized_product_roles),
        engagement__product__prod_type__authorized_group=Exists(engagement_authorized_product_type_groups),
        engagement__product__authorized_group=Exists(engagement_authorized_product_groups),
        product__prod_type__member=Exists(product_authorized_product_type_roles),
        product__member=Exists(product_authorized_product_roles),
        product__prod_type__authorized_group=Exists(product_authorized_product_type_groups),
        product__authorized_group=Exists(product_authorized_product_groups))
    jira_projects = jira_projects.filter(
        Q(engagement__product__prod_type__member=True) |
        Q(engagement__product__member=True) |
        Q(engagement__product__prod_type__authorized_group=True) |
        Q(engagement__product__authorized_group=True) |
        Q(product__prod_type__member=True) |
        Q(product__member=True) |
        Q(product__prod_type__authorized_group=True) |
        Q(product__authorized_group=True))

    return jira_projects


def get_authorized_jira_issues(permission):
    user = get_current_user()

    if user is None:
        return JIRA_Issue.objects.none()

    jira_issues = JIRA_Issue.objects.all()

    if user.is_superuser:
        return jira_issues

    if user_has_global_permission(user, permission):
        return jira_issues

    roles = get_roles_for_permission(permission)
    engagement_authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef('engagement__product__prod_type_id'),
        user=user,
        role__in=roles)
    engagement_authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef('engagement__product_id'),
        user=user,
        role__in=roles)
    engagement_authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('engagement__product__prod_type_id'),
        group__users=user,
        role__in=roles)
    engagement_authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('engagement__product_id'),
        group__users=user,
        role__in=roles)
    finding_group_authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef('finding_group__test__engagement__product__prod_type_id'),
        user=user,
        role__in=roles)
    finding_group_authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef('finding_group__test__engagement__product_id'),
        user=user,
        role__in=roles)
    finding_group_authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('finding_group__test__engagement__product__prod_type_id'),
        group__users=user,
        role__in=roles)
    finding_group_authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('finding_group__test__engagement__product_id'),
        group__users=user,
        role__in=roles)
    finding_authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef('finding__test__engagement__product__prod_type_id'),
        user=user,
        role__in=roles)
    finding_authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef('finding__test__engagement__product_id'),
        user=user,
        role__in=roles)
    finding_authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('finding__test__engagement__product__prod_type_id'),
        group__users=user,
        role__in=roles)
    finding_authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('finding__test__engagement__product_id'),
        group__users=user,
        role__in=roles)
    jira_issues = jira_issues.annotate(
        engagement__product__prod_type__member=Exists(engagement_authorized_product_type_roles),
        engagement__product__member=Exists(engagement_authorized_product_roles),
        engagement__product__prod_type__authorized_group=Exists(engagement_authorized_product_type_groups),
        engagement__product__authorized_group=Exists(engagement_authorized_product_groups),
        finding_group__test__engagement__product__prod_type__member=Exists(finding_group_authorized_product_type_roles),
        finding_group__test__engagement__product__member=Exists(finding_group_authorized_product_roles),
        finding_group__test__engagement__product__prod_type__authorized_group=Exists(finding_group_authorized_product_type_groups),
        finding_group__test__engagement__product__authorized_group=Exists(finding_group_authorized_product_groups),
        finding__test__engagement__product__prod_type__member=Exists(finding_authorized_product_type_roles),
        finding__test__engagement__product__member=Exists(finding_authorized_product_roles),
        finding__test__engagement__product__prod_type__authorized_group=Exists(finding_authorized_product_type_groups),
        finding__test__engagement__product__authorized_group=Exists(finding_authorized_product_groups))
    jira_issues = jira_issues.filter(
        Q(engagement__product__prod_type__member=True) |
        Q(engagement__product__member=True) |
        Q(engagement__product__prod_type__authorized_group=True) |
        Q(engagement__product__authorized_group=True) |
        Q(finding_group__test__engagement__product__prod_type__member=True) |
        Q(finding_group__test__engagement__product__member=True) |
        Q(finding_group__test__engagement__product__prod_type__authorized_group=True) |
        Q(finding_group__test__engagement__product__authorized_group=True) |
        Q(finding__test__engagement__product__prod_type__member=True) |
        Q(finding__test__engagement__product__member=True) |
        Q(finding__test__engagement__product__prod_type__authorized_group=True) |
        Q(finding__test__engagement__product__authorized_group=True))

    return jira_issues
