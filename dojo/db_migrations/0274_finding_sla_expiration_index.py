from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    # CREATE INDEX CONCURRENTLY cannot run inside a transaction block, and avoids
    # an ACCESS EXCLUSIVE lock on the (large) dojo_finding table.
    atomic = False

    dependencies = [
        ("dojo", "0273_product_upper_name_index"),
    ]

    operations = [
        # Full (non-partial) btree on sla_expiration_date. The global finding
        # list ordered by sla_expiration_date currently seq-scans + sorts the
        # entire authorized finding set; this lets the planner walk the index and
        # stop at the LIMIT. The existing partial idx_finding_sla_open_cov cannot
        # serve it because that query has no is_mitigated predicate.
        AddIndexConcurrently(
            model_name="finding",
            index=models.Index(
                fields=["sla_expiration_date"],
                name="idx_finding_sla_exp",
            ),
        ),
    ]
