from crum import get_current_user
from django.db.models import Q, Subquery

from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission
from dojo.models import JIRA_Issue, JIRA_Project, Product_Group, Product_Member, Product_Type_Group, Product_Type_Member
from dojo.request_cache import cache_for_request


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_jira_projects(permission, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return JIRA_Project.objects.none()

    jira_projects = JIRA_Project.objects.all().order_by("id")

    if user.is_superuser:
        return jira_projects

    if user_has_global_permission(user, permission):
        return jira_projects

    roles = get_roles_for_permission(permission)

    # Get authorized product/product_type IDs via subqueries
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_roles = Product_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_id")

    authorized_product_type_groups = Product_Type_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_groups = Product_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_id")

    # Filter using IN with Subquery - no annotations needed
    # JIRA projects can be attached via engagement or product path
    return jira_projects.filter(
        # Engagement path
        Q(engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(engagement__product_id__in=Subquery(authorized_product_groups))
        # Product path
        | Q(product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(product_id__in=Subquery(authorized_product_roles))
        | Q(product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(product_id__in=Subquery(authorized_product_groups)),
    )


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_jira_issues(permission):
    user = get_current_user()

    if user is None:
        return JIRA_Issue.objects.none()

    jira_issues = JIRA_Issue.objects.all().order_by("id")

    if user.is_superuser:
        return jira_issues

    if user_has_global_permission(user, permission):
        return jira_issues

    roles = get_roles_for_permission(permission)

    # Get authorized product/product_type IDs via subqueries
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_roles = Product_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_id")

    authorized_product_type_groups = Product_Type_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_groups = Product_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_id")

    # Filter using IN with Subquery - no annotations needed
    # JIRA issues can be attached via engagement, finding_group, or finding path
    return jira_issues.filter(
        # Engagement path
        Q(engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(engagement__product_id__in=Subquery(authorized_product_groups))
        # Finding group path
        | Q(finding_group__test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(finding_group__test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(finding_group__test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(finding_group__test__engagement__product_id__in=Subquery(authorized_product_groups))
        # Finding path
        | Q(finding__test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(finding__test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(finding__test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(finding__test__engagement__product_id__in=Subquery(authorized_product_groups)),
    )
