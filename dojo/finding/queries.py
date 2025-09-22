import logging

from crum import get_current_user
from django.conf import settings
from django.db.models import Case, CharField, Count, Exists, F, OuterRef, Q, Value, When
from django.db.models.functions import Concat
from django.db.models.query import Prefetch, QuerySet

from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission
from dojo.location.models import LocationFindingReference
from dojo.location.status import FindingLocationStatus
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
    if settings.V3_FEATURE_LOCATIONS:
        base_status = LocationFindingReference.objects.prefetch_related("location__url").all()
        prefetched_findings = prefetched_findings.annotate(
            has_endpoints=Exists(base_status),
            active_endpoint_count=Count(
                "locations",
                filter=Q(locations__status=FindingLocationStatus.Active),
                distinct=True,
            ),
            mitigated_endpoint_count=Count(
                "locations",
                filter=(~Q(locations__status=FindingLocationStatus.Active)),
                distinct=True,
            ),
        ).prefetch_related(
            Prefetch(
                "locations",
                queryset=base_status.filter(status=FindingLocationStatus.Active).annotate(is_broken=F("location__url__host_validation_failure"), object_id=F("location__id")).order_by("audit_time"),
                to_attr="active_endpoints",
            ),
            Prefetch(
                "locations",
                queryset=base_status.filter(~Q(status=FindingLocationStatus.Active)).annotate(is_broken=F("location__url__host_validation_failure"), object_id=F("location__id")).order_by("audit_time"),
                to_attr="mitigated_endpoints",
            ),
        )
    else:
        base_status = Endpoint_Status.objects.prefetch_related("endpoint")
        status = Case(
                When(
                    Q(false_positive=True) | Q(risk_accepted=True) | Q(out_of_scope=True) | Q(mitigated=True),
                    then=Concat(
                        Case(When(false_positive=True, then=Value("False Positive, ")), default=Value("")),
                        Case(When(risk_accepted=True, then=Value("Risk Accepted, ")), default=Value("")),
                        Case(When(out_of_scope=True, then=Value("Out of Scope, ")), default=Value("")),
                        Case(When(mitigated=True, then=Value("Mitigated, ")), default=Value("")),
                        output_field=CharField(),
                    ),
                ),
                default=Value("Active"),
                output_field=CharField(),
            )
        prefetched_findings = prefetched_findings.annotate(
            has_endpoints=Exists(base_status),
            active_endpoint_count=Count(
                "status_finding",
                filter=Q(
                    status_finding__mitigated=False,
                    status_finding__false_positive=False,
                    status_finding__out_of_scope=False,
                    status_finding__risk_accepted=False,
                ),
                distinct=True,
            ),
            mitigated_endpoint_count=Count(
                "status_finding",
                filter=(
                    Q(status_finding__mitigated=True)
                    | Q(status_finding__false_positive=True)
                    | Q(status_finding__out_of_scope=True)
                    | Q(status_finding__risk_accepted=True)
                ),
                distinct=True,
            ),
        ).prefetch_related(
            Prefetch(
                "status_finding",
                queryset=base_status.filter(
                    mitigated=False, false_positive=False, out_of_scope=False, risk_accepted=False,
                ).annotate(status=status, object_id=F("endpoint__id")).order_by("last_modified"),
                to_attr="active_endpoints",
            ),
            Prefetch(
                "status_finding",
                queryset=base_status.filter(
                    Q(mitigated=True) | Q(false_positive=True) | Q(out_of_scope=True) | Q(risk_accepted=True),
                ).annotate(status=status, object_id=F("endpoint__id")).order_by("mitigated_time"),
                to_attr="mitigated_endpoints",
            ),
        )

    return prefetched_findings
