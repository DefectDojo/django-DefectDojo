"""
Reverse of ``migrate_endpoints_to_locations``: materialize legacy ``Endpoint``/``Endpoint_Status``
rows from URL-type ``LocationFindingReference`` rows, for instances being returned to
``DD_V3_FEATURE_LOCATIONS=false`` after their imports wrote the Locations store.

Semantics, learned the hard way in production:

- **Create-only.** An existing ``(finding, endpoint)`` status row is NEVER touched: it predates the
  Locations write and holds the authoritative first-seen date and mitigation state. Reconciling
  current state is the next scheduled import's job, not this command's.
- **No M2M ``add()``.** ``Finding.endpoints`` is a through-model M2M over ``Endpoint_Status``;
  creating the status row IS the association, and ``add()`` would duplicate it with bare defaults.
- **URL-type rows only.** ``code`` and ``dependency`` locations have no legacy representation
  (findings keep ``file_path``/``component_name`` fields); they are counted and left in place.
- **Requires the flag OFF.** With ``DD_V3_FEATURE_LOCATIONS=true`` the ``Endpoint`` model refuses
  writes, so the command aborts up front with instructions instead of failing per row.
- Dry-run by default; ``--apply`` writes. Idempotent and convergent: re-runs skip everything that
  already exists. All writes carry a pghistory context (``source=migrate_locations_to_endpoints``).

Status mapping (FindingLocationStatus -> Endpoint_Status): Active -> unmitigated;
Mitigated -> mitigated (+ ``mitigated_time``/``mitigated_by`` from the reference audit trail);
FalsePositive / RiskAccepted / OutOfScope -> the matching boolean. ``date`` is the reference's
``created`` so first-seen history is preserved.
"""

import logging

import pghistory
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from dojo.endpoint.utils import endpoint_get_or_create
from dojo.location.models import LocationFindingReference
from dojo.location.status import FindingLocationStatus
from dojo.models import Endpoint, Endpoint_Status

logger = logging.getLogger(__name__)

CHUNK_SIZE = 500


class Command(BaseCommand):
    help = (
        "Create legacy Endpoint/Endpoint_Status rows from URL-type location references, for "
        "instances returning to DD_V3_FEATURE_LOCATIONS=false. Dry-run by default; --apply writes. "
        "Existing status rows are never modified."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Write the rows. Without this flag the command only reports what it would create.",
        )

    def handle(self, *args, **options):
        if settings.V3_FEATURE_LOCATIONS:
            msg = (
                "DD_V3_FEATURE_LOCATIONS is enabled, so the Endpoint model refuses writes. "
                "Set the flag to false (and restart services) before running this command."
            )
            raise CommandError(msg)

        apply_changes = bool(options["apply"])

        references = (
            LocationFindingReference.objects.filter(location__location_type="url")
            .select_related("location", "finding", "finding__test__engagement__product", "auditor")
            .order_by("id")
        )
        non_url = LocationFindingReference.objects.exclude(location__location_type="url").count()

        endpoints_created = statuses_created = skipped = 0
        failures: list[tuple[int, str]] = []

        for reference in references.iterator(chunk_size=CHUNK_SIZE):
            try:
                created_endpoint, created_status = self._materialize(reference, apply_changes=apply_changes)
                endpoints_created += created_endpoint
                statuses_created += created_status
                skipped += 0 if created_status else 1
            except Exception as exc:  # one bad row must not abort the run
                failures.append((reference.id, str(exc)))
                logger.warning("Could not materialize location reference %s: %s", reference.id, exc)

        mode = "APPLY" if apply_changes else "DRY-RUN"
        self.stdout.write(
            f"[{mode}] url references={references.count()} endpoints_created={endpoints_created} "
            f"statuses_created={statuses_created} skipped_existing={skipped} "
            f"non_url_references_left_in_place={non_url} failed={len(failures)}",
        )
        for reference_id, error in failures[:10]:
            self.stdout.write(f"  FAILED reference {reference_id}: {error}")

    def _materialize(self, reference, *, apply_changes: bool) -> tuple[int, int]:
        """Create the endpoint + status row for one reference; returns (endpoints, statuses) created."""
        finding = reference.finding
        parsed = Endpoint.from_uri(reference.location.location_value)
        endpoint_kwargs = {
            "protocol": parsed.protocol,
            "userinfo": parsed.userinfo,
            "host": parsed.host,
            "port": parsed.port,
            "path": parsed.path,
            "query": parsed.query,
            "fragment": parsed.fragment,
            "product": finding.test.engagement.product,
        }

        if not apply_changes:
            # Exercise parsing and traversal without writing; report as a would-create.
            return 0, 1

        mitigated = reference.status == FindingLocationStatus.Mitigated
        status_defaults = {
            "date": reference.created,
            "last_modified": reference.audit_time or reference.created or timezone.now(),
            "mitigated": mitigated,
            "mitigated_time": reference.audit_time if mitigated else None,
            "mitigated_by": reference.auditor if mitigated else None,
            "false_positive": reference.status == FindingLocationStatus.FalsePositive,
            "out_of_scope": reference.status == FindingLocationStatus.OutOfScope,
            "risk_accepted": reference.status == FindingLocationStatus.RiskAccepted,
        }

        with transaction.atomic(), pghistory.context(source="migrate_locations_to_endpoints"):
            endpoint, endpoint_created = endpoint_get_or_create(**endpoint_kwargs)
            _, status_created = Endpoint_Status.objects.get_or_create(
                finding=finding,
                endpoint=endpoint,
                defaults=status_defaults,
            )

        return int(endpoint_created), int(status_created)
