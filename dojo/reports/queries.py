
from django.conf import settings
from django.db.models import Prefetch, QuerySet

from dojo.authorization.roles_permissions import Permissions
from dojo.finding.queries import get_authorized_findings, prefetch_for_findings
from dojo.location.models import LocationFindingReference
from dojo.location.queries import annotate_location_counts_and_status
from dojo.location.status import FindingLocationStatus
from dojo.models import Finding


def prefetch_related_findings_for_report(findings: QuerySet) -> QuerySet:
    return prefetch_for_findings(
        findings.prefetch_related(
            # Some of the fields are removed here because they are being
            # prefetched in the prefetch_for_findings function
            "test__engagement__product__prod_type",
            "risk_acceptance_set__accepted_findings",
            "burprawrequestresponse_set",
            "files",
            "reporter",
            "mitigated_by",
        ),
    )


def prefetch_related_endpoints_for_report(endpoints: QuerySet, product=None, user=None) -> QuerySet:
    if settings.V3_FEATURE_LOCATIONS:
        # Reduce the prefetched references to the requesting user's product scope --
        # a Location is deduplicated across products, so its own auth check passes for
        # any associated product the user can see, but the findings hanging off it must
        # still be limited to that scope. Same reduction generate_report() applies to
        # its Location branch. user=None resolves to the current user, and to no
        # findings at all when there is none, so this fails closed.
        return annotate_location_counts_and_status(
            endpoints.prefetch_related(
                "tags",
                Prefetch(
                    "findings",
                    queryset=LocationFindingReference.objects.filter(
                        status=FindingLocationStatus.Active,
                        finding__in=get_authorized_findings(Permissions.Finding_View, user=user),
                    )
                    .prefetch_related("finding")
                    .order_by("finding__numerical_severity"),
                    to_attr="_active_annotated_findings",
                ),
            ),
        )
    # TODO: Delete this after the move to Locations
    findings_qs = Finding.objects.filter(
        active=True,
        out_of_scope=False,
        mitigated__isnull=True,
        false_p=False,
        duplicate=False,
        status_finding__false_positive=False,
        status_finding__out_of_scope=False,
        status_finding__risk_accepted=False,
    )
    if product is not None:
        findings_qs = findings_qs.filter(test__engagement__product=product)
    return endpoints.prefetch_related(
        "product",
        "tags",
        Prefetch(
            "findings",
            queryset=prefetch_for_findings(findings_qs.order_by("numerical_severity")),
            to_attr="active_annotated_findings",
        ),
    )
