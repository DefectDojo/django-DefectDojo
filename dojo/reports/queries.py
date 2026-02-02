
from django.conf import settings
from django.db.models import Prefetch, QuerySet

from dojo.finding.queries import prefetch_for_findings
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


def prefetch_related_endpoints_for_report(endpoints: QuerySet) -> QuerySet:
    if settings.V3_FEATURE_LOCATIONS:
        return annotate_location_counts_and_status(
            endpoints.prefetch_related(
                "tags",
                Prefetch(
                    "findings",
                    queryset=LocationFindingReference.objects.filter(status=FindingLocationStatus.Active)
                    .prefetch_related("finding")
                    .order_by("finding__numerical_severity"),
                    to_attr="_active_annotated_findings",
                ),
            ),
        )
    # TODO: Delete this after the move to Locations
    return endpoints.prefetch_related(
        "product",
        "tags",
        Prefetch(
            "findings",
            queryset=prefetch_for_findings(
                Finding.objects.filter(
                    active=True,
                    out_of_scope=False,
                    mitigated__isnull=True,
                    false_p=False,
                    duplicate=False,
                    status_finding__false_positive=False,
                    status_finding__out_of_scope=False,
                    status_finding__risk_accepted=False,
                ).order_by("numerical_severity"),
            ),
            to_attr="active_annotated_findings",
        ),
    )
