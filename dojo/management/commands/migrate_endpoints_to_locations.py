import contextlib
import datetime
import logging
import time

from django.core.management.base import BaseCommand
from django.db import connection
from django.db.models import Prefetch
from django.utils import timezone

from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.models import DojoMeta, Endpoint, Endpoint_Status
from dojo.url.models import URL

logger = logging.getLogger(__name__)

# Chunk size for the DB iterator. Tunable via --batch-size.
DEFAULT_BATCH_SIZE = 1000
# How often to emit per-chunk progress lines. Tunable via --progress-every.
DEFAULT_PROGRESS_EVERY = 50


# `LocationFindingReference.created` is `auto_now_add=True` (inherited from
# BaseModel). The original migration sets `created` to the source
# Endpoint_Status.date in a post-save UPDATE so that auto_now_add is
# bypassed. With bulk_create we don't get a post-save UPDATE; Django's
# SQLInsertCompiler.pre_save_val still calls Field.pre_save(add=True),
# which auto_now_add overrides with `now()`, ignoring our explicit value.
# The cleanest single-process fix is to temporarily flip auto_now_add off
# around the bulk write.
@contextlib.contextmanager
def _suspend_auto_now_add(model, field_name: str):
    field = model._meta.get_field(field_name)
    saved = field.auto_now_add
    field.auto_now_add = False
    try:
        yield
    finally:
        field.auto_now_add = saved


# Phases tracked by --benchmark. Order is preserved in the summary table.
PHASES = (
    "fetch_endpoint",   # iterator yields the next endpoint
    "url_create",       # URL.get_or_create_from_values + Location side-effect
    "tags",             # endpoint tag copy onto the location
    "meta",             # DojoMeta copy onto the location
    "finding_refs",     # LocationFindingReference creation per Endpoint_Status
    "product_refs",     # LocationProductReference creation
)


class Command(BaseCommand):

    """
    This management command creates a mapping from Endpoints and Endpoint Statuses to a new Locations system.
    The following occurs:
    - Endpoints -> URL (which will create a Location)
    - Products on Endpoint -> LocationProductReference
    - Findings on Endpoints -> LocationProductReference
    """

    help = "Usage: manage.py migrate_endpoints_to_locations"

    def add_arguments(self, parser):
        parser.add_argument(
            "--batch-size",
            type=int,
            default=DEFAULT_BATCH_SIZE,
            help=f"Endpoint.objects.iterator() chunk size (default: {DEFAULT_BATCH_SIZE}).",
        )
        parser.add_argument(
            "--progress-every",
            type=int,
            default=DEFAULT_PROGRESS_EVERY,
            help=f"Emit a progress line every N endpoints (default: {DEFAULT_PROGRESS_EVERY}).",
        )
        parser.add_argument(
            "--benchmark",
            action="store_true",
            help="Track per-phase wall-clock and print a summary table at the end.",
        )
        parser.add_argument(
            "--query-count",
            action="store_true",
            help="Force-debug the DB cursor and count queries per chunk. "
                 "Has measurable overhead; use only for profiling runs.",
        )

    # -- Per-phase timing helpers --------------------------------------------

    def _bench_start(self) -> float:
        return time.perf_counter() if self.benchmark else 0.0

    def _bench_end(self, phase: str, t0: float) -> None:
        if self.benchmark:
            self.timings[phase] += time.perf_counter() - t0
            self.counts[phase] += 1

    # -- Migration logic --------------------------------------------------

    def _endpoint_to_url(self, endpoint: Endpoint) -> Location:
        # Create the raw URL object first
        # This should create the location object as well
        t = self._bench_start()
        url = URL.get_or_create_from_values(
            protocol=endpoint.protocol,
            user_info=endpoint.userinfo,
            host=endpoint.host,
            port=endpoint.port,
            path=endpoint.path,
            query=endpoint.query,
            fragment=endpoint.fragment,
        )
        self._bench_end("url_create", t)

        # Add the endpoint tags to the location tags. Read names from the
        # prefetched `tags` manager and add them in a single splat call so we
        # do one round-trip per endpoint instead of one per tag.
        t = self._bench_start()
        tag_names = {tag.name for tag in endpoint.tags.all()}
        if tag_names:
            url.location.tags.add(*tag_names)
        self._bench_end("tags", t)

        # Add any metadata from the endpoint to the location.
        # bulk_create with ignore_conflicts mirrors the previous get_or_create
        # semantics — DojoMeta.unique_together = (location, name) so any
        # conflict is by definition the same row we'd otherwise have fetched.
        # One INSERT per endpoint instead of SELECT+INSERT per meta row.
        t = self._bench_start()
        meta_rows = [
            DojoMeta(name=m.name, value=m.value, location=url.location)
            for m in endpoint.endpoint_meta.all()
        ]
        if meta_rows:
            DojoMeta.objects.bulk_create(meta_rows, ignore_conflicts=True)
        self._bench_end("meta", t)

        return url.location

    def _convert_endpoint_status_to_string_status(self, endpoint_status: Endpoint_Status) -> str:
        """
        Start the conversion with the "special" statuses first since we are moving to a model
        of having a single status possible rather than a combo of many
        """
        if endpoint_status.risk_accepted:
            return FindingLocationStatus.RiskAccepted
        if endpoint_status.false_positive:
            return FindingLocationStatus.FalsePositive
        if endpoint_status.out_of_scope:
            return FindingLocationStatus.OutOfScope
        if endpoint_status.mitigated:
            return FindingLocationStatus.Mitigated
        # Default to Active
        return FindingLocationStatus.Active

    def _associate_location_with_findings(self, endpoint: Endpoint, location: Location) -> None:
        # Pull the prefetched list once. Avoids the redundant `.exists()` round-
        # trip the prior code did and lets the loop iterate prefetched data.
        statuses = list(endpoint.status_endpoint.all())

        # No findings — associate with the endpoint's product if one exists.
        if not statuses:
            if endpoint.product_id:
                t_p = self._bench_start()
                LocationProductReference.objects.bulk_create(
                    [LocationProductReference(
                        location=location,
                        product=endpoint.product,
                        status=ProductLocationStatus.Mitigated,
                        relationship="",
                        relationship_data={},
                    )],
                    ignore_conflicts=True,
                )
                self._bench_end("product_refs", t_p)
            return

        # Build LFR rows for every status, and build LPR rows deduplicated by
        # product, deriving the product status as Active iff any of THIS
        # endpoint's findings on that product are Active. This bypasses
        # `Location.associate_with_finding` (which would trigger full_clean
        # validation + the post_save inherit_tags signal per row) and is
        # semantically equivalent to the prior behavior in the common case
        # where each endpoint maps to a distinct location. As a side-effect
        # it also fixes the existing `associate_with_product` first-write-
        # wins bug (where a Mitigated status would stick even when later
        # Active findings come in for the same product).
        finding_refs: list[LocationFindingReference] = []
        product_status_by_id: dict[int, str] = {}
        product_obj_by_id: dict[int, object] = {}

        for endpoint_status in statuses:
            finding = endpoint_status.finding
            if finding is None:
                continue
            product = finding.test.engagement.product
            status = self._convert_endpoint_status_to_string_status(endpoint_status)
            # Endpoint_Status.date is a Date; the original code persisted
            # the same midnight-aware datetime in a post-save UPDATE. We
            # set it directly here — bulk_create skips auto_now_add so the
            # explicit value is honored.
            created_dt = timezone.make_aware(datetime.datetime(
                endpoint_status.date.year,
                endpoint_status.date.month,
                endpoint_status.date.day,
            ))
            finding_refs.append(LocationFindingReference(
                location=location,
                finding=finding,
                status=status,
                auditor=endpoint_status.mitigated_by,
                audit_time=endpoint_status.mitigated_time or endpoint_status.last_modified,
                relationship="",
                relationship_data={},
                created=created_dt,
            ))
            if product.id not in product_obj_by_id:
                product_obj_by_id[product.id] = product
                product_status_by_id[product.id] = (
                    ProductLocationStatus.Active
                    if status == FindingLocationStatus.Active
                    else ProductLocationStatus.Mitigated
                )
            elif (status == FindingLocationStatus.Active
                    and product_status_by_id[product.id] != ProductLocationStatus.Active):
                product_status_by_id[product.id] = ProductLocationStatus.Active

        t_f = self._bench_start()
        if finding_refs:
            with _suspend_auto_now_add(LocationFindingReference, "created"):
                LocationFindingReference.objects.bulk_create(
                    finding_refs, ignore_conflicts=True, batch_size=500,
                )
        self._bench_end("finding_refs", t_f)

        t_p = self._bench_start()
        if product_obj_by_id:
            product_refs = [
                LocationProductReference(
                    location=location,
                    product=product_obj_by_id[pid],
                    status=product_status_by_id[pid],
                    relationship="",
                    relationship_data={},
                )
                for pid in product_obj_by_id
            ]
            LocationProductReference.objects.bulk_create(
                product_refs, ignore_conflicts=True, batch_size=500,
            )
        self._bench_end("product_refs", t_p)

    # -- Progress + summary reporting ----------------------------------------

    @staticmethod
    def _fmt_duration(seconds: float) -> str:
        s = int(seconds)
        h, rem = divmod(s, 3600)
        m, s = divmod(rem, 60)
        if h:
            return f"{h}h {m}m"
        if m:
            return f"{m}m {s}s"
        return f"{s}s"

    def _log_progress(self, i: int, total: int, run_t0: float, queries_this_chunk: int | None) -> None:
        elapsed = time.time() - run_t0
        rate = i / elapsed if elapsed > 0 else 0.0
        remaining = (total - i) / rate if rate > 0 else 0.0
        pct = (i / total * 100.0) if total else 100.0
        line = (f"Migrated {i:,}/{total:,} endpoints ({pct:.1f}%) — "
                f"{rate:.1f} endpoints/sec — ETA {self._fmt_duration(remaining)}")
        if queries_this_chunk is not None:
            # Per-endpoint query count for this chunk window only.
            chunk_size = self.progress_every
            line += f" — {queries_this_chunk / chunk_size:.1f} queries/endpoint"
        self.stdout.write(self.style.SUCCESS(line))

        if self.benchmark:
            parts = [f"{p}={self.timings[p]:.1f}s" for p in PHASES]
            self.stdout.write("  " + "  ".join(parts))

    def _print_benchmark_summary(self, total_endpoints: int, total_seconds: float) -> None:
        if not self.benchmark:
            return
        total_phase = sum(self.timings.values()) or 1.0
        self.stdout.write(self.style.SUCCESS("=== Benchmark summary ==="))
        self.stdout.write(f"{'phase':<16}{'total_s':>10}{'per_endpoint_ms':>18}{'share':>10}")
        for phase in PHASES:
            t = self.timings[phase]
            per = (t * 1000.0 / total_endpoints) if total_endpoints else 0.0
            share = (t / total_phase * 100.0)
            self.stdout.write(f"{phase:<16}{t:>10.2f}{per:>18.2f}{share:>9.1f}%")
        self.stdout.write(f"{'(wall-clock)':<16}{total_seconds:>10.2f}"
                          f"{(total_seconds * 1000.0 / total_endpoints if total_endpoints else 0):>18.2f}"
                          f"{'100.0%':>10}")

    # -- handle ---------------------------------------------------------------

    def handle(self, *args, **options):
        self.benchmark = bool(options.get("benchmark"))
        self.query_count = bool(options.get("query_count"))
        self.batch_size = int(options["batch_size"])
        self.progress_every = int(options["progress_every"])

        # Per-phase wall-clock accumulators.
        self.timings = dict.fromkeys(PHASES, 0.0)
        self.counts = dict.fromkeys(PHASES, 0)

        if self.query_count:
            connection.force_debug_cursor = True
            queries_at_chunk_start = len(connection.queries)
        else:
            queries_at_chunk_start = 0  # unused

        # Allow endpoints to work with V3/Locations enabled
        with Endpoint.allow_endpoint_init():
            # Prefetch everything the per-endpoint loop will touch so the
            # iterator doesn't trigger N+1 joins:
            #   - `product` is select_related so we don't lazy-load it for the
            #     no-findings branch
            #   - `tags` and `endpoint_meta` are prefetched managers
            #   - `status_endpoint` is prefetched together with the FK chain
            #     `finding -> test -> engagement -> product` and `mitigated_by`
            #     so `associate_with_finding` can read them without queries.
            queryset = (
                Endpoint.objects.all()
                .select_related("product")
                .prefetch_related(
                    "tags",
                    "endpoint_meta",
                    Prefetch(
                        "status_endpoint",
                        queryset=Endpoint_Status.objects.select_related(
                            "finding__test__engagement__product",
                            "mitigated_by",
                        ),
                    ),
                )
            )
            # Grab the total count so we can communicate progress
            endpoint_count = queryset.count()
            self.stdout.write(self.style.WARNING(
                f"Starting migration of {endpoint_count:,} endpoints "
                f"(batch={self.batch_size}, progress every {self.progress_every}, "
                f"benchmark={'on' if self.benchmark else 'off'}, "
                f"query-count={'on' if self.query_count else 'off'})",
            ))

            run_t0 = time.time()
            i = 0
            # Process each endpoint
            for i, endpoint in enumerate(queryset.iterator(chunk_size=self.batch_size), 1):
                t_fetch = self._bench_start()
                # iterator already produced `endpoint`; bill nothing meaningful
                # to fetch_endpoint here — kept as a placeholder that B1's
                # prefetch will start incrementing.
                self._bench_end("fetch_endpoint", t_fetch)

                # Get the URL object first
                location = self._endpoint_to_url(endpoint)
                # Associate the URL with the findings associated with the Findings
                # the association to a finding will also apply to a product automatically
                self._associate_location_with_findings(endpoint, location)

                # Progress report every --progress-every endpoints
                if i % self.progress_every == 0:
                    queries_in_chunk = None
                    if self.query_count:
                        queries_in_chunk = len(connection.queries) - queries_at_chunk_start
                        # Trim the query log so memory doesn't balloon on long runs;
                        # after clear() the next chunk's baseline is 0.
                        connection.queries_log.clear()
                        queries_at_chunk_start = 0
                    self._log_progress(i, endpoint_count, run_t0, queries_in_chunk)

            elapsed = time.time() - run_t0
            self.stdout.write(self.style.SUCCESS(
                f"Done. Migrated {i:,} endpoints in {self._fmt_duration(elapsed)} "
                f"({(i / elapsed if elapsed else 0):.2f} endpoints/sec).",
            ))
            self._print_benchmark_summary(i, elapsed)

        if self.query_count:
            connection.force_debug_cursor = False
