"""
Case-insensitive tag lookups are served by an index on UPPER(name), on every tag table.

Tag fields are case-insensitive, so tagulous finds each tag it adds with ``get_or_create(name__iexact=...)``,
which compiles to ``UPPER("name"::text) = UPPER(%s)``; the importer, the bulk tag helpers and tag search
(``istartswith``) use the same expression. The unique index on ``name`` cannot serve it, so on an instance whose
tag table had grown to millions of rows every tag added to a finding was a sequential scan of that table
(a PATCH setting 12 tags: 18 s of SQL). ``dojo.0308`` indexes ``UPPER(name)`` on every tag table.
"""

import importlib
from unittest import mock

from django.apps import apps
from django.db import connection
from django_tagulous.models import BaseTagModel

from dojo.models import Finding, Product, Product_Type
from unittests.dojo_test_case import DojoTestCase

migration = importlib.import_module("dojo.db_migrations.0308_tag_name_upper_index")


def _tag_tables():
    return {
        model._meta.db_table for model in apps.get_models(include_auto_created=True) if issubclass(model, BaseTagModel)
    }


def _valid_upper_name_indexes():
    """{table: index name} for every valid index on UPPER(name) of a tag table."""
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT c.relname, ic.relname
            FROM pg_index i
            JOIN pg_class c ON c.oid = i.indrelid
            JOIN pg_class ic ON ic.oid = i.indexrelid
            WHERE i.indisvalid AND c.relname LIKE 'dojo_tagulous_%'
              AND pg_get_indexdef(i.indexrelid) LIKE '%(upper((name)::text) text_pattern_ops)'
            """,
        )
        return dict(cursor.fetchall())


def _plan(queryset):
    """
    The plan of ``queryset`` on a finding tag table of realistic size.

    On the few rows of a test database the planner may as well read the whole unique index on
    ``name`` and filter, so the table first gets 5,000 tags and fresh statistics (both rolled back
    with the test's transaction).
    """
    tag_model = Finding.tags.tag_model
    tag_model.objects.bulk_create(
        tag_model(name=f"upper-index-filler-{n}", slug=f"upper-index-filler-{n}", count=0, protected=False)
        for n in range(5000)
    )
    sql, params = queryset.query.sql_with_params()
    with connection.cursor() as cursor:
        cursor.execute(f"ANALYZE {tag_model._meta.db_table}")
        cursor.execute(f"EXPLAIN {sql}", params)
        return "\n".join(row[0] for row in cursor.fetchall())


class TagNameUpperIndexTest(DojoTestCase):
    def test_every_tag_table_has_a_valid_upper_name_index(self):
        tables = _tag_tables()
        self.assertIn("dojo_tagulous_finding_tags", tables)
        self.assertEqual(set(migration.TAG_TABLES), tables, "a new tag field needs its table in dojo.0308's list")
        indexes = _valid_upper_name_indexes()
        self.assertEqual(set(), tables - set(indexes))
        self.assertEqual({table: migration.index_name(table) for table in tables}, indexes)

    def test_the_lookup_that_adds_a_tag_uses_the_index(self):
        self.assertFalse(Finding.tags.tag_options.case_sensitive)
        plan = _plan(Finding.tags.tag_model.objects.filter(name__iexact="Some-Tag"))
        self.assertIn("using idx_tagulous_finding_tags_upper_name", plan)
        self.assertIn("Index Cond: (upper((name)::text) = 'SOME-TAG'::text)", plan)

    def test_a_prefix_tag_search_uses_the_index(self):
        plan = _plan(Finding.tags.tag_model.objects.filter(name__istartswith="some-"))
        self.assertIn("using idx_tagulous_finding_tags_upper_name", plan)
        self.assertIn("Index Cond: ((upper((name)::text) ~>=~ 'SOME-'::text)", plan)

    def test_adding_a_case_variant_reuses_the_existing_tag(self):
        prod_type = Product_Type.objects.create(name="Upper Index Type")
        first, second = (
            Product.objects.create(name=f"Upper Index Product {n}", description="tags", prod_type=prod_type)
            for n in (1, 2)
        )
        tag_model = Product.tags.tag_model
        first.tags.set(["Upper-Index-Tag"])
        existing = tag_model.objects.get(name__iexact="upper-index-tag")
        second.tags.set(["UPPER-INDEX-TAG"])
        self.assertEqual(
            [existing.id], list(tag_model.objects.filter(name__iexact="upper-index-tag").values_list("id", flat=True)),
        )
        self.assertEqual([existing.id], list(second.tags.values_list("id", flat=True)))
        self.assertEqual(2, tag_model.objects.get(id=existing.id).count)


class TagNameUpperIndexMigrationTest(DojoTestCase):

    """The migration's build choices, driven with a stand-in connection (a real INVALID index only comes out of an interrupted concurrent build)."""

    @staticmethod
    def _schema_editor(*, vendor="postgresql", in_atomic_block=False, indisvalid=None):
        cursor = mock.MagicMock()
        cursor.fetchone.return_value = None if indisvalid is None else (indisvalid,)
        db = mock.MagicMock(vendor=vendor, in_atomic_block=in_atomic_block)
        db.cursor.return_value.__enter__.return_value = cursor
        return mock.MagicMock(connection=db), cursor

    @staticmethod
    def _statements(cursor):
        return [call.args[0] for call in cursor.execute.call_args_list]

    def test_it_builds_concurrently_outside_a_transaction_and_analyzes_each_table(self):
        schema_editor, cursor = self._schema_editor()
        migration.add_indexes(apps, schema_editor)
        statements = self._statements(cursor)
        self.assertIn(
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS "idx_tagulous_finding_tags_upper_name" '
            'ON "dojo_tagulous_finding_tags" (UPPER("name"::text) text_pattern_ops)',
            statements,
        )
        self.assertIn('ANALYZE "dojo_tagulous_finding_tags"', statements)
        self.assertFalse(any(statement.startswith("DROP") for statement in statements))

    def test_it_builds_plainly_inside_a_transaction(self):
        schema_editor, cursor = self._schema_editor(in_atomic_block=True)
        migration.add_indexes(apps, schema_editor)
        creates = [statement for statement in self._statements(cursor) if statement.startswith("CREATE")]
        self.assertEqual(len(migration.TAG_TABLES), len(creates))
        self.assertTrue(all(statement.startswith("CREATE INDEX IF NOT EXISTS") for statement in creates))

    def test_it_drops_an_invalid_leftover_before_building_again(self):
        schema_editor, cursor = self._schema_editor(indisvalid=False)
        migration.add_indexes(apps, schema_editor)
        self.assertIn(
            'DROP INDEX CONCURRENTLY IF EXISTS "idx_tagulous_finding_tags_upper_name"',
            self._statements(cursor),
        )

    def test_it_keeps_a_valid_index(self):
        schema_editor, cursor = self._schema_editor(indisvalid=True)
        migration.add_indexes(apps, schema_editor)
        self.assertFalse(any(statement.startswith("DROP") for statement in self._statements(cursor)))

    def test_it_drops_every_index_when_unapplied(self):
        schema_editor, cursor = self._schema_editor()
        migration.remove_indexes(apps, schema_editor)
        self.assertEqual(
            [f'DROP INDEX CONCURRENTLY IF EXISTS "{migration.index_name(table)}"' for table in migration.TAG_TABLES],
            self._statements(cursor),
        )

    def test_it_does_nothing_on_another_database(self):
        for operation in (migration.add_indexes, migration.remove_indexes):
            schema_editor, cursor = self._schema_editor(vendor="sqlite")
            operation(apps, schema_editor)
            cursor.execute.assert_not_called()
