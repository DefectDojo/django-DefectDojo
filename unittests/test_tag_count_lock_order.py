"""
Concurrency test for the batched tag-count write in ``bulk_add_tag_mapping``.

Tagulous keeps a reference count on every tag row (``dojo_tagulous_finding_tags`` for
``Finding.tags``). ``bulk_add_tag_mapping``, which imports use for parser tags and inherited
tags, updates the counts of every tag it touched in a single ``UPDATE ... WHERE id IN (...)``.
That statement locks the rows in whatever order its plan reads them: an index scan reads them in
id order, but a sequential or bitmap heap scan reads them in physical order, which drifts away from
id order as every count update writes a new row version. Against a writer that takes the same rows
in ascending id order (``bulk_add_tags_to_instances``, ``bulk_remove_all_tags``, the import's test
tag write), two imports sharing tags could each hold a row the other one needed, and Postgres broke
the cycle with ``deadlock detected ... in relation "dojo_tagulous_finding_tags"``.

These tests use a second real database connection and real commits, which a ``TestCase`` cannot do
(see unittests/test_importers_test_tags_deadlock.py for the same pattern). The interleaving is
forced: the concurrent transaction takes its second row lock only once the batched write is blocked
on its first one. The plan is pinned to a sequential scan and the rows are arranged so that it reads
the higher id first, the order a heap scan reaches in production; the fix must hold whatever plan
the database picks.
"""

import threading
import time
import uuid

from django.db import OperationalError, connection, connections, transaction
from django.db.models import F
from django.test import SimpleTestCase
from django.utils import timezone

from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
)
from dojo.tags.utils import bulk_add_tag_mapping

WAIT_TIMEOUT_SECONDS = 20
# Pins the batched UPDATE to a heap scan, so it reads rows in physical (ctid) order.
HEAP_SCAN_ONLY = ("enable_indexscan", "enable_indexonlyscan", "enable_bitmapscan")


def _backend_pid():
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_backend_pid()")
        return cursor.fetchone()[0]


def _is_waiting_on_a_lock(pid):
    with connection.cursor() as cursor:
        cursor.execute("SELECT cardinality(pg_blocking_pids(%s)) > 0", [pid])
        return cursor.fetchone()[0]


def _wait_for(predicate, what):
    deadline = time.monotonic() + WAIT_TIMEOUT_SECONDS
    while not predicate():
        if time.monotonic() > deadline:
            msg = f"timed out after {WAIT_TIMEOUT_SECONDS}s waiting for {what}"
            raise AssertionError(msg)
        time.sleep(0.01)


class TestBulkAddTagMappingLockOrder(SimpleTestCase):

    databases = {"default"}

    def setUp(self):
        super().setUp()
        self.suffix = uuid.uuid4().hex[:12]
        # Nothing here is rolled back and the test database is kept between runs, so every row
        # these tests commit is removed again.
        self.user = User.objects.create(username=f"tag_lock_{self.suffix}")
        self.product_type = Product_Type.objects.create(name=f"Tag Lock PT {self.suffix}")
        self.product = Product.objects.create(
            name=f"Tag Lock Product {self.suffix}", description="Test", prod_type=self.product_type,
        )
        self.engagement = Engagement.objects.create(
            name=f"Tag Lock Engagement {self.suffix}",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.test_type = Test_Type.objects.create(name=f"Tag Lock {self.suffix}")
        self.test = Test.objects.create(
            engagement=self.engagement,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.tag_model = Finding.tags.tag_model
        self.addCleanup(self._remove_committed_rows)

    def _finding(self, title):
        return Finding.objects.create(
            test=self.test, title=f"{title} {self.suffix}", severity="High", reporter=self.user,
        )

    def _tag_name(self, label):
        return f"{self.suffix}-{label}"

    def _remove_committed_rows(self):
        for finding in Finding.objects.filter(test=self.test):
            finding.tags.clear()
        Finding.objects.filter(test=self.test).delete()
        Test.objects.filter(id=self.test.id).delete()
        Test_Type.objects.filter(id=self.test_type.id).delete()
        Engagement.objects.filter(id=self.engagement.id).delete()
        Product.objects.filter(id=self.product.id).delete()
        Product_Type.objects.filter(id=self.product_type.id).delete()
        User.objects.filter(id=self.user.id).delete()
        self.tag_model.objects.filter(name__startswith=self.suffix).delete()

    def _ctid_after(self, later_pk, earlier_pk):
        table = connection.ops.quote_name(self.tag_model._meta.db_table)
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT (SELECT ctid FROM {table} WHERE id = %s) > (SELECT ctid FROM {table} WHERE id = %s)",
                [later_pk, earlier_pk],
            )
            return cursor.fetchone()[0]

    def _store_rows_in_name_order(self):
        """
        Rewrite the tag table in tag name order (CLUSTER on its unique name index).

        Rewriting a row in place does not reliably move it past another one: page pruning hands its
        new version whichever line pointer it freed first, and a full page sends it to an earlier page.
        CLUSTER places every row by name, so the physical order is fixed by the names the test picks.
        """
        table = self.tag_model._meta.db_table
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT i.indexrelid::regclass::text FROM pg_index i"
                " JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]"
                " WHERE i.indrelid = %s::regclass AND i.indisunique AND i.indnatts = 1 AND a.attname = 'name'",
                [table],
            )
            name_index = cursor.fetchone()[0]
            cursor.execute(f"CLUSTER {connection.ops.quote_name(table)} USING {name_index}")

        def forget_cluster_index():
            with connection.cursor() as cursor:
                cursor.execute(f"ALTER TABLE {connection.ops.quote_name(table)} SET WITHOUT CLUSTER")

        self.addCleanup(forget_cluster_index)

    def _heap_scans_only(self):
        with connection.cursor() as cursor:
            for setting in HEAP_SCAN_ONLY:
                cursor.execute(f"SET {setting} = off")

        def reset():
            with connection.cursor() as cursor:
                for setting in HEAP_SCAN_ONLY:
                    cursor.execute(f"RESET {setting}")

        self.addCleanup(reset)

    # Regression: concurrent async imports failed with "deadlock detected ... while rechecking updated
    # tuple (...) in relation dojo_tagulous_finding_tags" when the batched count UPDATE took the rows in
    # heap order and another writer took them in id order.
    def test_batched_count_update_does_not_deadlock_an_id_ordered_tag_writer(self):
        # The lower-id tag gets the later name, so in name order (below) the higher id is stored first.
        low_name, high_name = self._tag_name("b"), self._tag_name("a")
        # Another finding already uses both tags, so the rows exist and nothing deletes them.
        other = self._finding("other")
        other.tags.set([low_name, high_name])
        low = self.tag_model.objects.get(name=low_name)
        high = self.tag_model.objects.get(name=high_name)
        self.assertLess(low.pk, high.pk)
        self._store_rows_in_name_order()
        self.assertTrue(self._ctid_after(low.pk, high.pk), "a heap scan must reach the higher id first")
        finding = self._finding("imported")
        self._heap_scans_only()

        main_pid = _backend_pid()
        writer_holds_low = threading.Event()
        batch_started = threading.Event()
        writer_errors = []

        def lock_low_then_high():
            # A concurrent writer updating the same two count rows in ascending id order.
            try:
                with connection.cursor() as cursor:
                    cursor.execute(f"SET lock_timeout = '{WAIT_TIMEOUT_SECONDS}s'")
                with transaction.atomic():
                    self.tag_model.objects.filter(pk=low.pk).update(count=F("count"))
                    writer_holds_low.set()
                    _wait_for(
                        lambda: batch_started.is_set() and _is_waiting_on_a_lock(main_pid),
                        "the batched tag write to wait on a tag row",
                    )
                    self.tag_model.objects.filter(pk=high.pk).update(count=F("count"))
            except BaseException as exc:
                writer_errors.append(exc)
            finally:
                connections.close_all()

        writer = threading.Thread(target=lock_low_then_high, daemon=True)
        writer.start()
        self.assertTrue(writer_holds_low.wait(WAIT_TIMEOUT_SECONDS), "the concurrent writer did not start")
        batch_started.set()
        try:
            created = bulk_add_tag_mapping({high_name: [finding], low_name: [finding]})
        except OperationalError as exc:
            self.fail(f"the batched tag write lost a lock conflict: {exc}")
        writer.join(WAIT_TIMEOUT_SECONDS)
        self.assertFalse(writer.is_alive(), "the concurrent writer did not finish")
        self.assertEqual(writer_errors, [], msg=f"the concurrent writer lost a lock conflict: {writer_errors}")
        self.assertEqual(created, 2)
        self.assertEqual({low_name, high_name}, set(Finding.objects.get(pk=finding.pk).tags.get_tag_list()))
        for tag in (low, high):
            tag.refresh_from_db()
            self.assertEqual(tag.count, 2, msg=f"{tag.name} is used by both findings")

    def test_batched_count_update_without_contention_keeps_counts(self):
        """Control: the ordered lock changes when the rows are locked, not what the write does."""
        shared, fresh = self._tag_name("shared"), self._tag_name("fresh")
        first, second = self._finding("first"), self._finding("second")
        first.tags.set([shared])

        created = bulk_add_tag_mapping({fresh: [first, second], shared: [first, second]})

        self.assertEqual(created, 3, "the existing (first, shared) pair is not added again")
        self.assertEqual(self.tag_model.objects.get(name=shared).count, 2)
        self.assertEqual(self.tag_model.objects.get(name=fresh).count, 2)
        self.assertEqual({shared, fresh}, set(Finding.objects.get(pk=second.pk).tags.get_tag_list()))
