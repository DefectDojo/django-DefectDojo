import contextlib
import datetime
import logging
import time
from collections import defaultdict
from itertools import islice

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import connection, transaction
from django.db.models import Case, Exists, OuterRef, Prefetch, Value, When
from django.utils import timezone

from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.models import DojoMeta, Endpoint, Endpoint_Status, Product
from dojo.tags.utils import bulk_add_tag_mapping
from dojo.url.models import URL

logger = logging.getLogger(__name__)

# Endpoints read per DB iterator chunk, and rows per bulk write. Tunable via
# --batch-size.
DEFAULT_BATCH_SIZE = 1000
# Minimum endpoints between progress lines. Tunable via --progress-every.
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


class _ChunkRows:

    """
    Rows accumulated for one chunk, deduplicated on their unique constraint.

    The migration builds every row for a chunk in memory and then issues one
    write per kind. Deduplicating here is what makes those writes safe: several
    legacy Endpoints can normalize onto a single Location, and Postgres rejects
    an ``ON CONFLICT DO UPDATE`` statement that would touch the same row twice.

    Each row is paired with the id of the endpoint that produced it so a failed
    batch write can be retried per row and attributed to the right endpoint.
    """

    def __init__(self) -> None:
        self.meta: list[DojoMeta] = []
        self.meta_endpoint_ids: list[int | None] = []
        self._seen_meta: set[tuple[int, str]] = set()

        self.finding_refs: list[LocationFindingReference] = []
        self.finding_ref_endpoint_ids: list[int | None] = []
        self._seen_finding_refs: set[tuple[int, int]] = set()

        # (location_id, product_id) -> (status, product, location, endpoint_id)
        self._product_refs: dict[tuple[int, int], tuple[str, Product, Location, int | None]] = {}

    def add_meta(self, meta: DojoMeta, location: Location, endpoint_id: int | None) -> None:
        """Queue a DojoMeta copy, keyed on its unique_together (location, name)."""
        key = (location.id, meta.name)
        if key in self._seen_meta:
            return
        self._seen_meta.add(key)
        self.meta.append(DojoMeta(name=meta.name, value=meta.value, location=location))
        self.meta_endpoint_ids.append(endpoint_id)

    def add_finding_ref(self, reference: LocationFindingReference, endpoint_id: int | None) -> None:
        """Queue a finding reference, keyed on its unique (location, finding)."""
        key = (reference.location.id, reference.finding_id)
        if key in self._seen_finding_refs:
            return
        self._seen_finding_refs.add(key)
        self.finding_refs.append(reference)
        self.finding_ref_endpoint_ids.append(endpoint_id)

    def record_product(
        self,
        product: Product,
        location: Location,
        status: str,
        endpoint_id: int | None,
    ) -> None:
        """
        Queue a product reference, letting Active win within the chunk.

        The status recorded here only reflects this chunk;
        ``_reconcile_product_statuses`` has the final say once every finding
        reference is in place.
        """
        key = (location.id, product.id)
        existing = self._product_refs.get(key)
        if existing is None or (
            status == ProductLocationStatus.Active
            and existing[0] != ProductLocationStatus.Active
        ):
            self._product_refs[key] = (status, product, location, endpoint_id)

    def product_ref_rows(self) -> tuple[list[LocationProductReference], list[int | None]]:
        rows = [
            LocationProductReference(
                location=location,
                product=product,
                status=status,
                relationship="",
                relationship_data={},
            )
            for status, product, location, _ in self._product_refs.values()
        ]
        endpoint_ids = [endpoint_id for _, _, _, endpoint_id in self._product_refs.values()]
        return rows, endpoint_ids


# Phases tracked by --benchmark. Order is preserved in the summary table.
PHASES = (
    "fetch_chunk",      # iterator + prefetch queries for the next chunk
    "url_create",       # URL.bulk_get_or_create + Location rows for the chunk
    "tags",             # batched endpoint tag copy onto locations
    "meta",             # DojoMeta copy onto the location
    "finding_refs",     # LocationFindingReference creation per Endpoint_Status
    "product_refs",     # LocationProductReference creation
    "reconcile",        # recompute product-reference status from finding refs
)


class Command(BaseCommand):

    """
    This management command creates a mapping from Endpoints and Endpoint Statuses to a new Locations system.
    The following occurs:
    - Endpoints -> URL (which will create a Location)
    - Products on Endpoint -> LocationProductReference
    - Findings on Endpoints -> LocationProductReference

    The command is safe to re-run and converges on the state the source
    Endpoints/Endpoint_Statuses describe:

    - ``URL``/``Location`` rows are matched on ``identity_hash``, so an endpoint
      that already migrated reuses its location instead of duplicating it.
    - ``LocationFindingReference`` is upserted on (location, finding): a status,
      auditor or audit time that has since changed on the source
      ``Endpoint_Status`` is written over the stale value, while the original
      ``created`` timestamp is preserved.
    - ``LocationProductReference`` status is recomputed from the finding
      references after each chunk, using the same rule as
      ``Location.status_from_product`` (Active when the location has at least
      one Active finding for that product). This repairs statuses left behind by
      an earlier run and makes the outcome independent of the order endpoints
      are visited in.
    - ``DojoMeta`` rows and tag copies are insert-only, so re-runs neither
      duplicate them nor overwrite edits made after the first migration.
    """

    help = "Usage: manage.py migrate_endpoints_to_locations"

    def add_arguments(self, parser):
        parser.add_argument(
            "--batch-size",
            type=int,
            default=DEFAULT_BATCH_SIZE,
            help="Endpoints read, and rows written, per batch "
                 f"(default: {DEFAULT_BATCH_SIZE}).",
        )
        parser.add_argument(
            "--progress-every",
            type=int,
            default=DEFAULT_PROGRESS_EVERY,
            help="Emit a progress line once at least N endpoints have been migrated "
                 "since the last one; lines land on batch boundaries, so a value "
                 f"below --batch-size reports once per batch (default: {DEFAULT_PROGRESS_EVERY}).",
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

    # -- Tag inheritance bookkeeping -----------------------------------------

    def _track_product_location(self, product: Product, location: Location) -> None:
        """
        Record a (product, location) pair for the post-migration tag inheritance pass.

        The migration creates locations that may be linked to multiple products
        (via the endpoint's own product and via each finding's product). We
        collect every contributing product per location so the post-pass can
        call ``apply_inherited_tags_for_locations`` once per product group —
        covering the case where a location is shared across products with
        differing ``enable_product_tag_inheritance`` flags (the helper
        short-circuits via its own diff check on repeat visits, so redundancy
        is safe).
        """
        if product is None or product.id is None:
            return
        if location is None or location.id is None:
            return
        self.locations_by_product_id[product.id].add(location.id)
        self.product_obj_by_id.setdefault(product.id, product)
        self.location_obj_by_id.setdefault(location.id, location)

    # -- Endpoint tag batching -----------------------------------------------

    def _queue_location_tags(
        self,
        endpoint: Endpoint,
        location: Location,
        tag_names: set[str],
    ) -> None:
        """Queue endpoint tags for a batched write to their destination Location."""
        if endpoint.id is None or location.id is None:
            return
        for tag_name in tag_names:
            # Multiple legacy Endpoints may normalize to the same Location.
            # Deduplicate by Location id so the through row and Tagulous count
            # are each updated exactly once.
            self.pending_tag_locations[tag_name][location.id] = location
        self.pending_endpoint_tags[endpoint.id] = (location, tag_names)

    def _record_endpoint_failure(self, endpoint_id: int | None, exc: Exception) -> None:
        """Record an Endpoint once even if more than one migration phase fails."""
        if endpoint_id in self.failed_endpoint_ids:
            return
        self.failed_endpoint_ids.add(endpoint_id)
        self.failed_endpoints.append((endpoint_id, str(exc)))

    def _flush_location_tags(self) -> None:
        """Persist queued tags, retrying per Endpoint if the batch write fails."""
        if not self.pending_tag_locations:
            return

        tag_to_locations = {
            tag_name: list(locations_by_id.values())
            for tag_name, locations_by_id in self.pending_tag_locations.items()
        }
        t = self._bench_start()
        try:
            try:
                # bulk_add_tag_mapping creates tags, through rows, and updates
                # Tagulous counters in separate steps. The outer transaction
                # makes the complete batch atomic if any step fails.
                with transaction.atomic():
                    bulk_add_tag_mapping(tag_to_locations, batch_size=self.batch_size)
            except Exception:
                endpoint_ids = list(self.pending_endpoint_tags)
                logger.exception(
                    "Batched endpoint tag copy failed for %d tagged endpoint(s); "
                    "first endpoint ids=%s; retrying one endpoint at a time",
                    len(endpoint_ids),
                    endpoint_ids[:10],
                )

                # Preserve the command's documented per-row resilience. This
                # slower path runs only after a failed batch and isolates a bad
                # Endpoint without discarding valid tag writes for its peers.
                for endpoint_id, (location, tag_names) in self.pending_endpoint_tags.items():
                    endpoint_mapping = {
                        tag_name: [location]
                        for tag_name in tag_names
                    }
                    try:
                        with transaction.atomic():
                            bulk_add_tag_mapping(endpoint_mapping, batch_size=self.batch_size)
                    except Exception as exc:
                        logger.exception(
                            "Failed to copy tags for endpoint id=%s; continuing",
                            endpoint_id,
                        )
                        self._record_endpoint_failure(endpoint_id, exc)
        finally:
            self._bench_end("tags", t)
            self.pending_tag_locations.clear()
            self.pending_endpoint_tags.clear()

    # -- Chunked reads ---------------------------------------------------------

    def _iter_chunks(self, queryset):
        """
        Yield lists of at most ``batch_size`` endpoints.

        ``queryset.iterator(chunk_size=...)`` already fetches and prefetches a
        chunk at a time, so re-buffering into a list of the same size costs no
        extra memory over what Django is already holding, and it gives the
        migration a batch to write in one shot per phase.
        """
        iterator = queryset.iterator(chunk_size=self.batch_size)
        while True:
            t = self._bench_start()
            chunk = list(islice(iterator, self.batch_size))
            self._bench_end("fetch_chunk", t)
            if not chunk:
                return
            yield chunk

    # -- Bulk writes with per-row fallback ------------------------------------

    def _bulk_create_rows(
        self,
        phase: str,
        model,
        rows: list,
        endpoint_ids: list[int | None],
        cm_factory=None,
        conflict_kwargs: dict | None = None,
    ) -> None:
        """
        Write ``rows`` in one ``bulk_create``, retrying per row if that fails.

        The whole chunk goes out as a single statement on the happy path. If it
        raises we fall back to one row at a time so a single bad row can't
        discard the valid rows it was batched with — the same
        batch-then-isolate shape ``_flush_location_tags`` uses. Failures are
        attributed to the endpoint that produced the row via
        ``endpoint_ids[i]``.

        ``conflict_kwargs`` selects the upsert behaviour (``ignore_conflicts``
        vs ``update_conflicts`` + ``update_fields``/``unique_fields``); callers
        must deduplicate rows on the conflict target first, because Postgres
        rejects a statement whose ``ON CONFLICT DO UPDATE`` would touch the
        same row twice.

        ``cm_factory`` is a callable returning a context manager to wrap each
        write (used for ``_suspend_auto_now_add``); it must be a factory rather
        than an instance because the retry path enters it once per row.
        """
        if not rows:
            return
        cm_factory = cm_factory or contextlib.nullcontext
        conflict_kwargs = conflict_kwargs or {"ignore_conflicts": True}
        t = self._bench_start()
        try:
            try:
                with cm_factory():
                    model.objects.bulk_create(
                        rows, batch_size=self.batch_size, **conflict_kwargs,
                    )
            except Exception:
                logger.exception(
                    "Batched %s write failed for %d row(s); "
                    "retrying one row at a time",
                    phase, len(rows),
                )
                for row, endpoint_id in zip(rows, endpoint_ids, strict=True):
                    try:
                        with transaction.atomic(), cm_factory():
                            model.objects.bulk_create([row], **conflict_kwargs)
                    except Exception as exc:
                        logger.exception(
                            "Failed to write %s row for endpoint id=%s; continuing",
                            phase, endpoint_id,
                        )
                        self._record_endpoint_failure(endpoint_id, exc)
        finally:
            self._bench_end(phase, t)

    def _reconcile_product_statuses(self, location_ids: list[int]) -> None:
        """
        Recompute ``LocationProductReference.status`` for the chunk's locations.

        A product reference is Active exactly when the location has at least
        one Active finding reference for that product — the same rule
        ``Location.status_from_product`` applies. Recomputing it from the
        finding refs in one set-based UPDATE per chunk is what makes re-runs
        converge:

        - it repairs stale statuses left by an earlier run (or by the previous
          first-write-wins behaviour of ``associate_with_product``);
        - it is order independent, so a location shared by endpoints in
          different chunks ends up Active if *any* of its findings is Active,
          without the migration having to remember cross-chunk state.

        Only locations touched by this chunk are considered, so the statement
        stays bounded no matter how large the install is.
        """
        if not location_ids:
            return
        t = self._bench_start()
        try:
            has_active_finding = LocationFindingReference.objects.filter(
                location_id=OuterRef("location_id"),
                finding__test__engagement__product_id=OuterRef("product_id"),
                status=FindingLocationStatus.Active,
            )
            try:
                LocationProductReference.objects.filter(
                    location_id__in=location_ids,
                ).update(
                    status=Case(
                        When(Exists(has_active_finding), then=Value(ProductLocationStatus.Active)),
                        default=Value(ProductLocationStatus.Mitigated),
                    ),
                    updated=timezone.now(),
                )
            except Exception:
                # Reconciliation is a repair pass over rows that are already
                # committed, so a failure here costs accuracy on this chunk's
                # statuses, not data. Keep going rather than abort the run.
                logger.exception(
                    "Product-reference status reconciliation failed for %d location(s); "
                    "continuing", len(location_ids),
                )
        finally:
            self._bench_end("reconcile", t)

    # -- Migration logic --------------------------------------------------

    def _resolve_locations(self, endpoints: list[Endpoint]) -> list[tuple[Endpoint, Location]]:
        """
        Resolve one Location per endpoint for the whole chunk.

        ``URL.bulk_get_or_create`` does the work in ~3 queries per chunk (one
        lookup by ``identity_hash`` plus a ``bulk_create`` for the parent
        Location rows and the URL rows) in place of the per-endpoint
        ``get_or_create``, which cost a savepoint pair, a SELECT, a
        ``validate_unique`` SELECT and two INSERTs each.

        Each URL is validated individually first. ``bulk_get_or_create`` only
        calls ``clean()``, whereas the per-endpoint ``save()`` this replaces ran
        ``full_clean()`` — so validating here keeps an endpoint whose values
        can't pass field validation (empty host, out-of-range port, …) from
        being written as an invalid Location, and reports it against its own id
        instead of taking the chunk down. ``validate_unique`` is left off: the
        identity_hash lookup ``bulk_get_or_create`` already does resolves
        duplicates without a SELECT per row.

        If the bulk write itself still fails we fall back to the per-endpoint
        ``get_or_create`` path for the chunk, which migrates every good endpoint
        and attributes the failure to the one that caused it.
        """
        t = self._bench_start()
        try:
            pairs: list[tuple[Endpoint, URL]] = []
            for endpoint in endpoints:
                url = URL.from_parts(
                    protocol=endpoint.protocol,
                    user_info=endpoint.userinfo,
                    host=endpoint.host,
                    port=endpoint.port,
                    path=endpoint.path,
                    query=endpoint.query,
                    fragment=endpoint.fragment,
                )
                try:
                    # Mirrors what BaseModelWithoutTimeMeta.save() would have
                    # done for this URL, including the flag it keys off.
                    if settings.V3_FEATURE_LOCATIONS:
                        url.full_clean(validate_unique=False, validate_constraints=False)
                    else:
                        url.clean()
                except Exception as exc:
                    endpoint_id = getattr(endpoint, "id", None)
                    logger.exception(
                        "Failed to migrate endpoint id=%s; continuing", endpoint_id,
                    )
                    self._record_endpoint_failure(endpoint_id, exc)
                    continue
                pairs.append((endpoint, url))

            if not pairs:
                return []

            try:
                saved = URL.bulk_get_or_create([url for _, url in pairs])
            except Exception:
                logger.exception(
                    "Bulk location resolution failed for %d endpoint(s); "
                    "falling back to one get_or_create per endpoint",
                    len(pairs),
                )
                resolved = []
                for endpoint, url in pairs:
                    try:
                        resolved.append((endpoint, URL.get_or_create_from_object(url).location))
                    except Exception as exc:
                        endpoint_id = getattr(endpoint, "id", None)
                        logger.exception(
                            "Failed to migrate endpoint id=%s; continuing", endpoint_id,
                        )
                        self._record_endpoint_failure(endpoint_id, exc)
                return resolved

            return [
                (endpoint, saved_url.location)
                for (endpoint, _), saved_url in zip(pairs, saved, strict=True)
            ]
        finally:
            self._bench_end("url_create", t)

    def _process_chunk(self, endpoints: list[Endpoint]) -> None:
        """
        Migrate a chunk of endpoints with one bulk write per phase.

        Everything between the location resolve and the writes is pure Python
        over already-prefetched data, so the DB sees a fixed handful of
        statements per chunk rather than a dozen per endpoint.
        """
        resolved = self._resolve_locations(endpoints)
        if not resolved:
            return

        rows = _ChunkRows()
        for endpoint, location in resolved:
            endpoint_id = getattr(endpoint, "id", None)
            try:
                # Queue endpoint tags for one bulk write per chunk instead of
                # making Tagulous look up and attach tags once per endpoint.
                t = self._bench_start()
                tag_names = {tag.name for tag in endpoint.tags.all()}
                if tag_names:
                    self._queue_location_tags(endpoint, location, tag_names)
                self._bench_end("tags", t)

                for meta in endpoint.endpoint_meta.all():
                    rows.add_meta(meta, location, endpoint_id)

                # Track the endpoint's own product as a contributor for the
                # post-migration tag inheritance pass (the no-findings branch
                # of `_collect_references` also depends on this product, and it
                # won't be tracked otherwise).
                if endpoint.product_id:
                    self._track_product_location(endpoint.product, location)

                self._collect_references(endpoint, location, rows)
            except Exception as exc:
                logger.exception("Failed to migrate endpoint id=%s; continuing", endpoint_id)
                self._record_endpoint_failure(endpoint_id, exc)

        # DojoMeta: `ignore_conflicts` on unique_together (location, name). A
        # conflict is by definition the row we would otherwise have fetched, so
        # skipping it keeps re-runs no-ops and leaves any post-migration edit to
        # a metadata value alone.
        self._bulk_create_rows("meta", DojoMeta, rows.meta, rows.meta_endpoint_ids)

        # LocationFindingReference: upsert on (location, finding) so a re-run
        # syncs the status/auditor/audit_time when the source Endpoint_Status
        # has moved on. `created` is deliberately absent from update_fields —
        # the original creation timestamp is preserved on repeat runs.
        self._bulk_create_rows(
            "finding_refs", LocationFindingReference,
            rows.finding_refs, rows.finding_ref_endpoint_ids,
            cm_factory=lambda: _suspend_auto_now_add(LocationFindingReference, "created"),
            conflict_kwargs={
                "update_conflicts": True,
                "update_fields": ["status", "auditor", "audit_time", "updated"],
                "unique_fields": ["location", "finding"],
            },
        )

        # LocationProductReference: insert-only. The status carried here is
        # derived from this chunk alone, so it is not authoritative — the
        # reconciliation pass below recomputes it from the finding refs.
        product_ref_rows, product_ref_endpoint_ids = rows.product_ref_rows()
        self._bulk_create_rows(
            "product_refs", LocationProductReference,
            product_ref_rows, product_ref_endpoint_ids,
        )

        self._reconcile_product_statuses(list({location.id for _, location in resolved}))

    def _collect_references(
        self,
        endpoint: Endpoint,
        location: Location,
        rows: _ChunkRows,
    ) -> None:
        """
        Accumulate this endpoint's finding/product reference rows.

        Pure Python over the prefetched ``status_endpoint`` list — no queries.
        Bypasses ``Location.associate_with_finding`` (which would trigger
        full_clean validation plus the post_save inherit_tags signal per row)
        and is semantically equivalent to it for this migration.
        """
        endpoint_id = getattr(endpoint, "id", None)

        # Pull the prefetched list once. Avoids the redundant `.exists()` round-
        # trip the prior code did and lets the loop iterate prefetched data.
        statuses = list(endpoint.status_endpoint.all())

        # No findings — associate with the endpoint's product if one exists.
        if not statuses:
            if endpoint.product_id:
                rows.record_product(
                    endpoint.product, location, ProductLocationStatus.Mitigated, endpoint_id,
                )
            return

        for endpoint_status in statuses:
            finding = endpoint_status.finding
            if finding is None:
                continue
            product = finding.test.engagement.product
            # Track this contributing product for the post-migration tag
            # inheritance pass (covers the case where a finding's product
            # differs from endpoint.product).
            self._track_product_location(product, location)
            status = self._convert_endpoint_status_to_string_status(endpoint_status)
            rows.record_product(
                product,
                location,
                ProductLocationStatus.Active
                if status == FindingLocationStatus.Active
                else ProductLocationStatus.Mitigated,
                endpoint_id,
            )

            # Endpoint_Status.date is a Date; the original code persisted
            # the same midnight-aware datetime in a post-save UPDATE. We
            # set it directly here — bulk_create skips auto_now_add so the
            # explicit value is honored.
            created_dt = timezone.make_aware(datetime.datetime(
                endpoint_status.date.year,
                endpoint_status.date.month,
                endpoint_status.date.day,
            ))
            rows.add_finding_ref(LocationFindingReference(
                location=location,
                finding=finding,
                status=status,
                auditor=endpoint_status.mitigated_by,
                audit_time=endpoint_status.mitigated_time or endpoint_status.last_modified,
                relationship="",
                relationship_data={},
                created=created_dt,
            ), endpoint_id)

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

    def _log_progress(
        self,
        i: int,
        total: int,
        run_t0: float,
        queries_this_window: int | None,
        endpoints_this_window: int,
    ) -> None:
        elapsed = time.time() - run_t0
        rate = i / elapsed if elapsed > 0 else 0.0
        remaining = (total - i) / rate if rate > 0 else 0.0
        pct = (i / total * 100.0) if total else 100.0
        line = (f"Migrated {i:,}/{total:,} endpoints ({pct:.1f}%) — "
                f"{rate:.1f} endpoints/sec — ETA {self._fmt_duration(remaining)}")
        if queries_this_window is not None and endpoints_this_window:
            # Per-endpoint query count for this reporting window only.
            line += f" — {queries_this_window / endpoints_this_window:.1f} queries/endpoint"
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

    # -- Post-migration tag inheritance --------------------------------------

    def _run_tag_inheritance(self) -> None:
        """
        Apply inherited tags once per contributing product.

        Each product batch is wrapped in its own try/except so a
        failure on one product group doesn't prevent the rest from running —
        same philosophy as the per-endpoint loop. The underlying
        location/reference rows are already committed by the main loop, so
        partial failure here leaves a consistent (if incompletely reconciled)
        inheritance state that a targeted re-run can finish.
        """
        if not self.locations_by_product_id:
            return

        # Lazy import: the inheritance module imports the full model layer, so
        # keep it out of management-command discovery.
        from dojo.tags import inheritance as tag_inheritance  # noqa: PLC0415

        t0 = time.time()
        n_products = len(self.locations_by_product_id)
        n_pairs = sum(len(loc_ids) for loc_ids in self.locations_by_product_id.values())
        n_unique_locations = len(self.location_obj_by_id)
        n_failures = 0
        for prod_id, loc_ids in self.locations_by_product_id.items():
            product = self.product_obj_by_id[prod_id]
            locations = [self.location_obj_by_id[lid] for lid in loc_ids]
            try:
                tag_inheritance.apply_inherited_tags_for_locations(
                    locations,
                    product=product,
                )
            except Exception:
                logger.exception(
                    "Tag inheritance pass failed for product id=%s "
                    "(%d location(s)); continuing with remaining products",
                    prod_id, len(locations),
                )
                n_failures += 1
        elapsed = time.time() - t0
        msg = (
            f"Tag inheritance pass: visited {n_pairs:,} (product, location) pair(s) "
            f"across {n_products:,} product(s), {n_unique_locations:,} unique location(s), "
            f"in {elapsed:.2f}s"
        )
        if n_failures:
            self.stdout.write(self.style.WARNING(f"{msg} — {n_failures} product group(s) failed"))
        else:
            self.stdout.write(self.style.SUCCESS(msg))

    # -- handle ---------------------------------------------------------------

    def handle(self, *args, **options):
        self.benchmark = bool(options.get("benchmark"))
        self.query_count = bool(options.get("query_count"))
        self.batch_size = int(options["batch_size"])
        self.progress_every = int(options["progress_every"])

        # Per-phase wall-clock accumulators.
        self.timings = dict.fromkeys(PHASES, 0.0)
        self.counts = dict.fromkeys(PHASES, 0)

        # Bookkeeping for the post-migration tag inheritance pass.
        # `locations_by_product_id` maps product.id -> set of location.ids
        # contributed by that product (via endpoint.product OR finding.test.
        # engagement.product). We hold the Product/Location objects in
        # parallel maps so the post-pass can hand them directly to the bulk
        # inheritance helper.
        self.locations_by_product_id: dict[int, set[int]] = defaultdict(set)
        self.product_obj_by_id: dict[int, Product] = {}
        self.location_obj_by_id: dict[int, Location] = {}

        # Endpoint tags are copied to Locations once per migration batch.
        # The nested Location-id mapping prevents duplicate through rows and
        # tag-count drift when multiple Endpoints normalize to one Location.
        self.pending_tag_locations: dict[str, dict[int, Location]] = defaultdict(dict)
        self.pending_endpoint_tags: dict[int, tuple[Location, set[str]]] = {}

        # Collected per-endpoint failures so a single bad row doesn't abort
        # a multi-hour migration. Each entry is (endpoint_id, exception_str).
        self.failed_endpoints: list[tuple[int | None, str]] = []
        self.failed_endpoint_ids: set[int | None] = set()

        if self.query_count:
            connection.force_debug_cursor = True
        queries_at_window_start = len(connection.queries) if self.query_count else 0

        # Lazy import: the inheritance module imports the full model layer, so
        # keep it out of management-command discovery.
        from dojo.tags import inheritance as tag_inheritance  # noqa: PLC0415

        # Allow endpoints to work with V3/Locations enabled, and keep the
        # per-instance tag-inheritance signals out of the hot loop.
        #
        # Every `Location` row created here fires `inherit_tags_on_instance`,
        # which calls `Location.all_related_products()` — an OR across two
        # multi-join paths (`LocationProductReference` and
        # `Finding -> Test -> Engagement -> Product` via
        # `LocationFindingReference`) that Postgres can only answer by
        # materialising the whole join and filtering it. Because this migration
        # is itself filling `LocationFindingReference`, that query gets more
        # expensive with every endpoint migrated, which is what turned the run
        # into an O(n^2) crawl (~105ms of the ~132ms each `Location` insert
        # cost, on a small dataset, growing from there).
        #
        # The work is redundant regardless: a freshly created Location has no
        # product references yet, so the signal has nothing to inherit. Correct
        # inheritance is applied in bulk by `_run_tag_inheritance()` once the
        # references exist, which is why that pass already exists.
        with Endpoint.allow_endpoint_init():
            # Prefetch everything the per-endpoint loop will touch so the
            # iterator doesn't trigger N+1 joins:
            #   - `product` is select_related so we don't lazy-load it for the
            #     no-findings branch
            #   - `tags` and `endpoint_meta` are prefetched managers
            #   - `status_endpoint` is prefetched together with the FK chain
            #     `finding -> test -> engagement -> product` and `mitigated_by`
            #     so the reference rows can be built without queries.
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
            last_reported = 0
            # Process endpoints a chunk at a time. Each chunk issues a fixed
            # handful of statements — one lookup + two inserts for the
            # locations, then one write per reference/meta/tag phase — instead
            # of a dozen round trips per endpoint. `_process_chunk` isolates
            # failures itself: per-endpoint for anything that can raise while
            # building rows, and per-row on a failed batch write, so one bad
            # endpoint still can't abort a multi-hour migration.
            with tag_inheritance.suppress_tag_inheritance():
                for chunk in self._iter_chunks(queryset):
                    self._process_chunk(chunk)
                    i += len(chunk)

                    # Flush independently of per-endpoint success so a failing
                    # endpoint at a chunk boundary cannot leave the queue growing.
                    self._flush_location_tags()

                    # Progress report once at least --progress-every endpoints
                    # have been migrated since the last line.
                    if i - last_reported >= self.progress_every or i >= endpoint_count:
                        queries_in_window = None
                        if self.query_count:
                            queries_in_window = len(connection.queries) - queries_at_window_start
                            # Trim the query log so memory doesn't balloon on long runs;
                            # after clear() the next window's baseline is 0.
                            connection.queries_log.clear()
                            queries_at_window_start = 0
                        self._log_progress(
                            i, endpoint_count, run_t0, queries_in_window, i - last_reported,
                        )
                        last_reported = i

            elapsed = time.time() - run_t0
            successful = i - len(self.failed_endpoints)
            self.stdout.write(self.style.SUCCESS(
                f"Done. Migrated {successful:,}/{i:,} endpoints in {self._fmt_duration(elapsed)} "
                f"({(i / elapsed if elapsed else 0):.2f} endpoints/sec).",
            ))
            if self.failed_endpoints:
                preview_ids = [eid for eid, _ in self.failed_endpoints[:10]]
                self.stdout.write(self.style.WARNING(
                    f"{len(self.failed_endpoints):,} endpoint(s) failed; see logger output above "
                    f"for tracebacks. First failing endpoint IDs: {preview_ids}",
                ))

            # Run the post-migration tag inheritance pass. `bulk_create` skips
            # the `inherit_tags_on_linked_instance` post_save signal, so for
            # deployments with `enable_product_tag_inheritance` enabled (per
            # product or system-wide) the migrated Locations would otherwise
            # not pick up inherited product tags. We grouped (product,
            # location) pairs during the main loop and now drive
            # `apply_inherited_tags_for_locations` once per contributing
            # product. The helper rediscovers each location's full product
            # set via LocationProductReference/LocationFindingReference and
            # diff-checks before writing, so revisits of shared locations
            # across product groups are idempotent.
            self._run_tag_inheritance()

            self._print_benchmark_summary(i, elapsed)

        if self.query_count:
            connection.force_debug_cursor = False
