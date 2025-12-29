import logging
from functools import partial

from crum import get_current_user
from django.db.models import OuterRef, Q, Subquery, Value
from django.db.models.functions import Coalesce
from django.db.models.query import Prefetch, QuerySet

from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission
from dojo.models import (
    IMPORT_UNTOUCHED_FINDING,
    Endpoint_Status,
    Finding,
    Product_Group,
    Product_Member,
    Product_Type_Group,
    Product_Type_Member,
    Stub_Finding,
    Test_Import_Finding_Action,
    Vulnerability_Id,
)
from dojo.query_utils import build_count_subquery
from dojo.request_cache import cache_for_request

logger = logging.getLogger(__name__)


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_findings(permission, user=None):
    """Cached - returns all findings the user is authorized to see."""
    if user is None:
        user = get_current_user()
    if user is None:
        return Finding.objects.none()
    findings = Finding.objects.all().order_by("id")

    if user.is_superuser:
        return findings

    if user_has_global_permission(user, permission):
        return findings

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
    return findings.filter(
        Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_groups)),
    )


def get_authorized_findings_for_queryset(permission, queryset, user=None):
    """Filters a provided queryset for authorization. Not cached due to dynamic queryset parameter."""
    if user is None:
        user = get_current_user()
    if user is None:
        return Finding.objects.none()
    findings = Finding.objects.all().order_by("id") if queryset is None else queryset

    if user.is_superuser:
        return findings

    if user_has_global_permission(user, permission):
        return findings

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
    return findings.filter(
        Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_groups)),
    )


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_stub_findings(permission):
    user = get_current_user()

    if user is None:
        return Stub_Finding.objects.none()

    if user.is_superuser:
        return Stub_Finding.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Stub_Finding.objects.all().order_by("id")

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
    return Stub_Finding.objects.filter(
        Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_groups)),
    ).order_by("id")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_vulnerability_ids(permission, user=None):
    """Cached - returns all vulnerability IDs the user is authorized to see."""
    if user is None:
        user = get_current_user()

    if user is None:
        return Vulnerability_Id.objects.none()

    vulnerability_ids = Vulnerability_Id.objects.all()

    if user.is_superuser:
        return vulnerability_ids

    if user_has_global_permission(user, permission):
        return vulnerability_ids

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
    return vulnerability_ids.filter(
        Q(finding__test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(finding__test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(finding__test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(finding__test__engagement__product_id__in=Subquery(authorized_product_groups)),
    )


def get_authorized_vulnerability_ids_for_queryset(permission, queryset, user=None):
    """Filters a provided queryset for authorization. Not cached due to dynamic queryset parameter."""
    if user is None:
        user = get_current_user()

    if user is None:
        return Vulnerability_Id.objects.none()

    if user.is_superuser:
        return queryset

    if user_has_global_permission(user, permission):
        return queryset

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
    return queryset.filter(
        Q(finding__test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(finding__test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(finding__test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(finding__test__engagement__product_id__in=Subquery(authorized_product_groups)),
    )


def prefetch_for_findings(findings, prefetch_type="all", *, exclude_untouched=True):
    """
    Unified prefetch function for findings across the application.

    Args:
        findings: QuerySet of findings to prefetch
        prefetch_type: "all" or "open" - controls risk acceptance prefetching
        exclude_untouched: Whether to exclude untouched import actions

    """
    if not isinstance(findings, QuerySet):
        logger.debug("unable to prefetch because query was already executed")
        return findings

    # Base prefetches - always needed
    prefetched_findings = findings.prefetch_related(
        "reviewers",
        "jira_issue__jira_project__jira_instance",
        "test__test_type",
        "test__engagement__jira_project__jira_instance",
        "test__engagement__product__jira_project_set__jira_instance",
        "found_by",
        "reporter",
    )

    # Conditional prefetches for non-open findings
    if prefetch_type != "open":
        prefetched_findings = prefetched_findings.prefetch_related(
            "risk_acceptance_set",
            "risk_acceptance_set__accepted_findings",
            "original_finding",
            "duplicate_finding",
        )

    # Import actions - configurable filtering
    if exclude_untouched:
        prefetched_findings = prefetched_findings.prefetch_related(
            Prefetch(
                "test_import_finding_action_set",
                queryset=Test_Import_Finding_Action.objects.exclude(action=IMPORT_UNTOUCHED_FINDING),
            ),
        )
    else:
        prefetched_findings = prefetched_findings.prefetch_related("test_import_finding_action_set")

    # Standard prefetches
    prefetched_findings = prefetched_findings.prefetch_related(
        "notes",
        "tags",
        "endpoints",
        "status_finding",
        "finding_group_set",
        "finding_group_set__jira_issue",  # Include both variants
        "test__engagement__product__members",
        "test__engagement__product__prod_type__members",
        "vulnerability_id_set",
    )

    # Endpoint counts using optimized subqueries
    base_status = Endpoint_Status.objects.filter(finding_id=OuterRef("pk"))
    count_subquery = partial(build_count_subquery, group_field="finding_id")
    return prefetched_findings.annotate(
        active_endpoint_count=Coalesce(count_subquery(base_status.filter(mitigated=False)), Value(0)),
        mitigated_endpoint_count=Coalesce(count_subquery(base_status.filter(mitigated=True)), Value(0)),
    )
