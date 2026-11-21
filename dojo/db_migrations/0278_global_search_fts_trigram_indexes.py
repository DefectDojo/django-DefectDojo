"""
Full-text-search and fuzzy-match GIN indexes for global search.

Adds, on the ten models the Pro global search (``pro/search/``) queries:

* one weighted ``tsvector`` GIN index per model, built from the same
  ``SearchVector`` objects the query annotates with, so the index expression
  can never drift from the compiled SQL across Django upgrades; and
* one ``gin_trgm_ops`` index on each model's short display column for the
  fuzzy ``%>`` (``__trigram_word_similar``) lookup.

Each index is declared on its model's ``Meta.indexes``; this migration is the
paired ``AddIndexConcurrently`` that actually builds them (the same house
style as the other functional-index migrations, e.g. 0273). The tsvector
indexes are built from the same ``SearchVector`` objects the query annotates
with, so the index expression cannot drift from the compiled SQL across Django
upgrades. The trigram indexes use ``opclasses`` (a base ``Index`` option), so
they need no ``OpClass`` expression.

``AddIndexConcurrently`` / ``CREATE EXTENSION`` cannot run inside a
transaction, hence ``atomic = False``. ``TrigramExtension`` is the sole
creator of ``pg_trgm`` here, so its symmetric reverse (dropping the extension
after the trigram indexes are already gone) is correct.
"""

import logging
import time

from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.operations import AddIndexConcurrently, TrigramExtension
from django.contrib.postgres.search import SearchVector
from django.db import migrations

# (model_name, ((column, weight), ...), index_name) -- weighted tsvector GIN.
logger = logging.getLogger(__name__)


class AddIndexConcurrentlyIfMissing(AddIndexConcurrently):

    """
    AddIndexConcurrently that can be re-run after a partial failure (copied from 0305).

    A CREATE INDEX CONCURRENTLY that is interrupted (the process is killed, the
    connection drops) leaves the index in the catalog marked INVALID, and a retry
    then fails with "relation ... already exists". Because this migration is not
    atomic, an earlier operation may also have finished before a later one failed.
    So: keep a valid index of the same name, drop an invalid leftover, then build.
    Migration state is unchanged from AddIndexConcurrently.

    Killing the migration process does not stop its build on the server, which
    runs on to completion. A build of this index that is still in progress is
    waited for first, so a retry keeps its result instead of dropping and
    rebuilding it.
    """

    poll_seconds = 5

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        self._ensure_not_in_transaction(schema_editor)
        model = to_state.apps.get_model(app_label, self.model_name)
        if not self.allow_migrate_model(schema_editor.connection.alias, model):
            return
        quoted_name = schema_editor.quote_name(self.index.name)
        with schema_editor.connection.cursor() as cursor:
            if self._build_in_progress(cursor, quoted_name):
                logger.warning("Waiting for an earlier build of index %s to finish", self.index.name)
                while self._build_in_progress(cursor, quoted_name):
                    time.sleep(self.poll_seconds)
                logger.warning("Earlier build of index %s finished", self.index.name)
            cursor.execute(
                "SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass(%s)",
                [quoted_name],
            )
            row = cursor.fetchone()
        if row is not None:
            if row[0]:
                return
            schema_editor.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {quoted_name}")
        schema_editor.add_index(model, self.index, concurrently=True)

    @staticmethod
    def _build_in_progress(cursor, quoted_name):
        cursor.execute(
            "SELECT 1 FROM pg_stat_progress_create_index"
            " WHERE index_relid = to_regclass(%s) AND pid <> pg_backend_pid()",
            [quoted_name],
        )
        return cursor.fetchone() is not None


_FTS_SPECS = (
    ("finding", (("title", "A"), ("description", "B")), "dojo_finding_fts_gin"),
    ("product", (("name", "A"), ("description", "B")), "dojo_product_fts_gin"),
    ("product_type", (("name", "A"), ("description", "B")), "dojo_product_type_fts_gin"),
    ("engagement", (("name", "A"), ("description", "B")), "dojo_engagement_fts_gin"),
    ("test", (("title", "A"), ("description", "B")), "dojo_test_fts_gin"),
    ("endpoint", (("host", "A"), ("path", "B")), "dojo_endpoint_fts_gin"),
    ("location", (("location_value", "A"), ("location_type", "B")), "dojo_location_fts_gin"),
    ("finding_template", (("title", "A"), ("description", "B")), "dojo_finding_template_fts_gin"),
    ("app_analysis", (("name", "A"),), "dojo_app_analysis_fts_gin"),
    ("vulnerability_id", (("vulnerability_id", "A"),), "dojo_vulnerability_id_fts_gin"),
)

# (model_name, column, index_name) -- gin_trgm_ops fuzzy-match index. Three
# names are abbreviated to stay within the 30-char index-name limit (E033):
# location_value -> locval, finding_template -> findtmpl, vulnerability_id -> vuln_id.
_TRGM_SPECS = (
    ("finding", "title", "dojo_finding_title_trgm"),
    ("product", "name", "dojo_product_name_trgm"),
    ("product_type", "name", "dojo_product_type_name_trgm"),
    ("engagement", "name", "dojo_engagement_name_trgm"),
    ("test", "title", "dojo_test_title_trgm"),
    ("endpoint", "host", "dojo_endpoint_host_trgm"),
    ("location", "location_value", "dojo_location_locval_trgm"),
    ("finding_template", "title", "dojo_findtmpl_title_trgm"),
    ("app_analysis", "name", "dojo_app_analysis_name_trgm"),
    ("vulnerability_id", "vulnerability_id", "dojo_vuln_id_trgm"),
)


def _fts_vector(fields):
    vector = None
    for column, weight in fields:
        component = SearchVector(column, weight=weight, config="english")
        vector = component if vector is None else vector + component
    return vector


def _index_operations():
    add_index = []
    for model_name, fields, name in _FTS_SPECS:
        add_index.append(
            AddIndexConcurrentlyIfMissing(
                model_name=model_name,
                index=GinIndex(_fts_vector(fields), name=name),
            ),
        )
    for model_name, column, name in _TRGM_SPECS:
        add_index.append(
            AddIndexConcurrentlyIfMissing(
                model_name=model_name,
                index=GinIndex(fields=[column], opclasses=["gin_trgm_ops"], name=name),
            ),
        )
    return [TrigramExtension(), *add_index]


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("dojo", "0277_seed_deduplication_execution_mode"),
    ]

    operations = _index_operations()
