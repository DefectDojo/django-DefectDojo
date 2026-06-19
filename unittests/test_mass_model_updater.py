"""
Tests for mass_model_updater performance optimizations:
  - skip-unchanged: rows whose tracked fields did not change are not written.
  - fast VALUES UPDATE: on PostgreSQL with simple scalar fields, writes use a
    single `UPDATE ... FROM (VALUES ...)` join instead of bulk_update's CASE/WHEN.
Both must remain byte-for-byte correct (incl. NULLs) and fall back to bulk_update
for non-postgres backends / non-simple fields.
"""

from django.db import connection
from django.test.utils import CaptureQueriesContext

from dojo.finding.deduplication import hashcode_values_writer
from dojo.models import Finding
from dojo.utils import mass_model_updater

from .dojo_test_case import DojoTestCase, versioned_fixtures


def _updates(captured):
    return [q["sql"] for q in captured if q["sql"].lstrip().upper().startswith("UPDATE")]


@versioned_fixtures
class TestMassModelUpdater(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def _finding_ids(self, n=5):
        return list(Finding.objects.exclude(duplicate=True).values_list("id", flat=True)[:n])

    def test_writes_changed_values(self):
        ids = self._finding_ids()
        qs = Finding.objects.filter(id__in=ids)

        def fn(f):
            f.hash_code = f"changed-{f.id}"

        mass_model_updater(Finding, qs, fn, fields=["hash_code"], order="asc")

        for fid in ids:
            self.assertEqual(
                Finding.objects.get(id=fid).hash_code,
                f"changed-{fid}",
                msg=f"finding {fid} hash_code not persisted",
            )

    def test_skips_unchanged_rows(self):
        # Regression/perf: re-running over already-correct rows must issue NO UPDATE.
        ids = self._finding_ids()
        # First, set known values.
        mass_model_updater(
            Finding, Finding.objects.filter(id__in=ids),
            lambda f: setattr(f, "hash_code", f"v-{f.id}"), fields=["hash_code"], order="asc",
        )
        # Now recompute to the SAME values → expect zero UPDATE statements.
        with CaptureQueriesContext(connection) as ctx:
            mass_model_updater(
                Finding, Finding.objects.filter(id__in=ids),
                lambda f: setattr(f, "hash_code", f"v-{f.id}"), fields=["hash_code"], order="asc",
            )
        self.assertEqual(
            len(_updates(ctx.captured_queries)), 0,
            msg=f"expected 0 UPDATEs for unchanged rows, got: {_updates(ctx.captured_queries)}",
        )

    def test_handles_null_values(self):
        ids = self._finding_ids()
        qs = Finding.objects.filter(id__in=ids)

        def fn(f):
            # alternate None / value to exercise NULL in the VALUES list
            f.hash_code = None if f.id % 2 == 0 else f"h-{f.id}"

        mass_model_updater(Finding, qs, fn, fields=["hash_code"], order="asc")

        for fid in ids:
            expected = None if fid % 2 == 0 else f"h-{fid}"
            self.assertEqual(
                Finding.objects.get(id=fid).hash_code, expected,
                msg=f"finding {fid} hash_code mismatch (null handling)",
            )

    def test_writer_hook_is_used_for_changed_rows(self):
        # A caller-supplied writer replaces bulk_update for persisting batches.
        ids = self._finding_ids()
        calls = []

        def writer(model_type, batch, fields):
            calls.append((model_type, [m.id for m in batch], list(fields)))
            model_type.objects.bulk_update(batch, fields)

        mass_model_updater(
            Finding, Finding.objects.filter(id__in=ids),
            lambda f: setattr(f, "hash_code", f"w-{f.id}"), fields=["hash_code"],
            order="asc", writer=writer,
        )
        written_ids = sorted(i for _, batch_ids, _ in calls for i in batch_ids)
        self.assertEqual(written_ids, sorted(ids), msg=f"writer not called for all changed rows: {calls}")
        for fid in ids:
            self.assertEqual(Finding.objects.get(id=fid).hash_code, f"w-{fid}")

    def test_writer_hook_not_called_when_nothing_changed(self):
        ids = self._finding_ids()
        mass_model_updater(
            Finding, Finding.objects.filter(id__in=ids),
            lambda f: setattr(f, "hash_code", f"s-{f.id}"), fields=["hash_code"], order="asc",
        )
        called = []
        mass_model_updater(
            Finding, Finding.objects.filter(id__in=ids),
            lambda f: setattr(f, "hash_code", f"s-{f.id}"), fields=["hash_code"],
            order="asc", writer=lambda *a: called.append(a),
        )
        self.assertEqual(called, [], msg="writer must not be called when no row changed")

    def test_skip_unchanged_can_be_disabled(self):
        ids = self._finding_ids()
        mass_model_updater(
            Finding, Finding.objects.filter(id__in=ids),
            lambda f: setattr(f, "hash_code", f"x-{f.id}"), fields=["hash_code"], order="asc",
        )
        with CaptureQueriesContext(connection) as ctx:
            mass_model_updater(
                Finding, Finding.objects.filter(id__in=ids),
                lambda f: setattr(f, "hash_code", f"x-{f.id}"), fields=["hash_code"],
                order="asc", skip_unchanged=False,
            )
        self.assertGreater(
            len(_updates(ctx.captured_queries)), 0,
            msg="skip_unchanged=False must still write unchanged rows",
        )

    def test_hashcode_values_writer_uses_values_sql_on_postgres(self):
        if connection.vendor != "postgresql":
            self.skipTest("VALUES fast path is postgres-only")
        objs = list(Finding.objects.filter(id__in=self._finding_ids()))
        for o in objs:
            o.hash_code = f"vw-{o.id}"
        with CaptureQueriesContext(connection) as ctx:
            hashcode_values_writer(Finding, objs, ["hash_code"])
        ups = _updates(ctx.captured_queries)
        self.assertTrue(any("from (values" in u.lower() for u in ups), msg=f"expected VALUES update, got: {ups}")
        self.assertFalse(any("case when" in u.lower() for u in ups), msg=f"unexpected CASE WHEN: {ups}")
        for o in objs:
            self.assertEqual(Finding.objects.get(id=o.id).hash_code, f"vw-{o.id}")

    def test_hashcode_values_writer_handles_null(self):
        objs = list(Finding.objects.filter(id__in=self._finding_ids()))
        for i, o in enumerate(objs):
            o.hash_code = None if i % 2 == 0 else f"vn-{o.id}"
        hashcode_values_writer(Finding, objs, ["hash_code"])
        for i, o in enumerate(objs):
            expected = None if i % 2 == 0 else f"vn-{o.id}"
            self.assertEqual(Finding.objects.get(id=o.id).hash_code, expected)

    def test_fields_none_calls_function_without_writing(self):
        ids = self._finding_ids()
        seen = []
        with CaptureQueriesContext(connection) as ctx:
            mass_model_updater(
                Finding, Finding.objects.filter(id__in=ids),
                lambda f: seen.append(f.id), fields=None, order="asc",
            )
        self.assertEqual(sorted(seen), sorted(ids), msg="function must run for every model")
        self.assertEqual(len(_updates(ctx.captured_queries)), 0, msg="fields=None must not write")
