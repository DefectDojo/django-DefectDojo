from django.db import migrations

from dojo.finding.cwe import cwe_label

BATCH_SIZE = 1000


def create_finding_cwe_records(apps, schema_editor):
    """Backfill Finding_CWE rows (canonical CWE-<n>) from the legacy int Finding.cwe field."""
    Finding = apps.get_model("dojo", "Finding")
    Finding_CWE = apps.get_model("dojo", "Finding_CWE")
    batch = []
    for finding in Finding.objects.filter(cwe__gt=0).only("id", "cwe").iterator(chunk_size=BATCH_SIZE):
        label = cwe_label(finding.cwe)
        if label is None:
            continue
        batch.append(Finding_CWE(finding_id=finding.id, cwe=label))
        if len(batch) >= BATCH_SIZE:
            Finding_CWE.objects.bulk_create(batch, batch_size=BATCH_SIZE, ignore_conflicts=True)
            batch = []
    if batch:
        Finding_CWE.objects.bulk_create(batch, batch_size=BATCH_SIZE, ignore_conflicts=True)


class Migration(migrations.Migration):

    """Data only (no schema changes): create the initial Finding_CWE rows from the legacy
    Finding.cwe field."""

    dependencies = [
        ("dojo", "0279_finding_cwe"),
    ]

    operations = [
        migrations.RunPython(create_finding_cwe_records, migrations.RunPython.noop),
    ]
