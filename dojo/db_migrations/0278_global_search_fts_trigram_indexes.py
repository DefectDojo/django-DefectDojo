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

from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.operations import AddIndexConcurrently, TrigramExtension
from django.contrib.postgres.search import SearchVector
from django.db import migrations

# (model_name, ((column, weight), ...), index_name) -- weighted tsvector GIN.
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
            AddIndexConcurrently(
                model_name=model_name,
                index=GinIndex(_fts_vector(fields), name=name),
            ),
        )
    for model_name, column, name in _TRGM_SPECS:
        add_index.append(
            AddIndexConcurrently(
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
