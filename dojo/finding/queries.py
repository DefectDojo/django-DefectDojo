import logging
from functools import partial

from crum import get_current_user
from django.db.models import Exists, OuterRef, Q, Value
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

logger = logging.getLogger(__name__)


def get_authorized_groups(permission, user=None):
    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef("test__engagement__product__prod_type_id"),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("test__engagement__product_id"),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("test__engagement__product__prod_type_id"),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("test__engagement__product_id"),
        group__users=user,
        role__in=roles)

    return (
        authorized_product_type_roles,
        authorized_product_roles,
        authorized_product_type_groups,
        authorized_product_groups,
    )


def get_authorized_findings(permission, queryset=None, user=None):
    if user is None:
        user = get_current_user()
    if user is None:
        return Finding.objects.none()
    findings = Finding.objects.all().order_by("id") if queryset is None else queryset

    if user.is_superuser:
        return findings

    if user_has_global_permission(user, permission):
        return findings

    (
        authorized_product_type_roles,
        authorized_product_roles,
        authorized_product_type_groups,
        authorized_product_groups,
    ) = get_authorized_groups(permission, user=user)

    findings = findings.annotate(
        test__engagement__product__prod_type__member=Exists(authorized_product_type_roles),
        test__engagement__product__member=Exists(authorized_product_roles),
        test__engagement__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        test__engagement__product__authorized_group=Exists(authorized_product_groups))
    return findings.filter(
        Q(test__engagement__product__prod_type__member=True)
        | Q(test__engagement__product__member=True)
        | Q(test__engagement__product__prod_type__authorized_group=True)
        | Q(test__engagement__product__authorized_group=True))


def get_authorized_stub_findings(permission):
    user = get_current_user()

    if user is None:
        return Stub_Finding.objects.none()

    if user.is_superuser:
        return Stub_Finding.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Stub_Finding.objects.all().order_by("id")

    (
        authorized_product_type_roles,
        authorized_product_roles,
        authorized_product_type_groups,
        authorized_product_groups,
    ) = get_authorized_groups(permission, user=user)

    findings = Stub_Finding.objects.annotate(
        test__engagement__product__prod_type__member=Exists(authorized_product_type_roles),
        test__engagement__product__member=Exists(authorized_product_roles),
        test__engagement__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        test__engagement__product__authorized_group=Exists(authorized_product_groups)).order_by("id")
    return findings.filter(
        Q(test__engagement__product__prod_type__member=True)
        | Q(test__engagement__product__member=True)
        | Q(test__engagement__product__prod_type__authorized_group=True)
        | Q(test__engagement__product__authorized_group=True))


def get_authorized_vulnerability_ids(permission, queryset=None, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return Vulnerability_Id.objects.none()

    vulnerability_ids = Vulnerability_Id.objects.all() if queryset is None else queryset

    if user.is_superuser:
        return vulnerability_ids

    if user_has_global_permission(user, permission):
        return vulnerability_ids

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef("finding__test__engagement__product__prod_type_id"),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("finding__test__engagement__product_id"),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("finding__test__engagement__product__prod_type_id"),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("finding__test__engagement__product_id"),
        group__users=user,
        role__in=roles)
    vulnerability_ids = vulnerability_ids.annotate(
        finding__test__engagement__product__prod_type__member=Exists(authorized_product_type_roles),
        finding__test__engagement__product__member=Exists(authorized_product_roles),
        finding__test__engagement__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        finding__test__engagement__product__authorized_group=Exists(authorized_product_groups))
    return vulnerability_ids.filter(
        Q(finding__test__engagement__product__prod_type__member=True)
        | Q(finding__test__engagement__product__member=True)
        | Q(finding__test__engagement__product__prod_type__authorized_group=True)
        | Q(finding__test__engagement__product__authorized_group=True))


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
