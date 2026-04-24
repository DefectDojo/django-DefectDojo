import logging

from django.db import migrations
from django.db.models import Q

logger = logging.getLogger(__name__)


AFFECTED_PARSER_SCAN_TYPES = [
    "Trivy Scan",
    "Trivy Operator Scan",
    "Hydra Scan",
    "JFrog Xray API Summary Artifact Scan",
    "Orca Security Alerts",
    "OpenReports",
    "StackHawk HawkScan",
]


def clear_service_and_rehash_findings(apps, schema_editor):
    """
    Clear parser-populated service values for affected parser scan types and
    recompute hash_code.

    This migration only touches findings where:
    - the finding belongs to an affected parser by test_type or scan_type
    - service is set (not NULL and not empty)
    """
    historical_finding = apps.get_model("dojo", "Finding")

    affected_ids = set()
    for scan_type in AFFECTED_PARSER_SCAN_TYPES:
        findings = (
            historical_finding.objects
            .filter(
                Q(test__test_type__name=scan_type)
                | Q(test__scan_type=scan_type),
            )
            .exclude(service__isnull=True)
            .exclude(service="")
        )
        count = findings.count()
        if count:
            logger.warning(
                "Identified %d findings with parser-populated service for scan type '%s'",
                count,
                scan_type,
            )
            affected_ids.update(findings.values_list("id", flat=True))

    if not affected_ids:
        logger.warning("No findings found for parser service cleanup migration")
        return

    # Use live model here to access compute_hash_code() and save() behavior.
    from dojo.models import Finding  # noqa: PLC0415

    migrated = 0
    for finding in (
        Finding.objects
        .filter(id__in=affected_ids)
        .select_related("test", "test__test_type")
        .iterator(chunk_size=200)
    ):
        finding.service = None
        finding.hash_code = finding.compute_hash_code()
        finding.save(
            dedupe_option=False,
            rules_option=False,
            product_grading_option=False,
            issue_updater_option=False,
            push_to_jira=False,
        )
        migrated += 1

    logger.warning(
        "Parser service cleanup migration updated %d findings (service cleared, hash_code recomputed)",
        migrated,
    )


def noop_reverse(apps, schema_editor):
    # Intentionally irreversible: previous parser-populated service values are not recoverable.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0263_language_type_unique_language"),
    ]

    operations = [
        migrations.RunPython(clear_service_and_rehash_findings, noop_reverse),
    ]
