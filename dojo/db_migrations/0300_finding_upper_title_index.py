from django.contrib.postgres.indexes import OpClass
from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models
from django.db.models.functions import Upper


class Migration(migrations.Migration):
    # CREATE INDEX CONCURRENTLY cannot run inside a transaction block, and avoids
    # an ACCESS EXCLUSIVE lock on the (large) dojo_finding table.
    atomic = False

    dependencies = [
        ("dojo", "0299_finding_test_numsev_index"),
    ]

    operations = [
        # Btree on UPPER(title). Every case-insensitive title filter compiles to
        # UPPER("dojo_finding"."title"::text), so neither the plain title index nor
        # the trigram index can serve it and each one reads every title. Measured on
        # 2,000,000 findings: iexact 351 ms -> 0.4 ms, an IN list of 50 upper-cased
        # titles 345 ms -> 6.9 ms, istartswith 347 ms -> 1.4 ms. text_pattern_ops
        # lets the same index serve the LIKE 'prefix%' that istartswith renders.
        AddIndexConcurrently(
            model_name="finding",
            index=models.Index(
                OpClass(Upper("title"), name="text_pattern_ops"),
                name="idx_finding_upper_title",
            ),
        ),
        # Gather statistics for the new UPPER(title) expression now. Without them the
        # planner overestimates an IN list by orders of magnitude and walks another
        # index (a 50-title count took 333 ms, against 1.2 ms once analyzed), and
        # autovacuum may not re-analyze a large, settled findings table for a long
        # time. ANALYZE reads a fixed-size sample: 0.9 s on 2,000,000 findings.
        migrations.RunSQL("ANALYZE dojo_finding", reverse_sql=migrations.RunSQL.noop),
    ]
