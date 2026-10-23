from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):

    # CREATE INDEX CONCURRENTLY cannot run inside a transaction, and a plain
    # CREATE INDEX would lock dojo_finding and dojo_endpoint_status for the whole build.
    atomic = False

    dependencies = [
        ("dojo", "0303_archive_columns"),
    ]

    operations = [
        AddIndexConcurrently(
            model_name="findingvulnerabilityreference",
            index=models.Index(condition=models.Q(("archive_batch__isnull", False)), fields=["archive_batch"], name="dojo_findvulnref_archive_batch"),
        ),
        AddIndexConcurrently(
            model_name="endpoint_status",
            index=models.Index(condition=models.Q(("archive_batch__isnull", False)), fields=["archive_batch"], name="dojo_endpstatus_archive_batch"),
        ),
        AddIndexConcurrently(
            model_name="engagement",
            index=models.Index(condition=models.Q(("archive_batch__isnull", False)), fields=["archive_batch"], name="dojo_engagement_archive_batch"),
        ),
        AddIndexConcurrently(
            model_name="finding",
            index=models.Index(condition=models.Q(("archive_batch__isnull", False)), fields=["archive_batch"], name="dojo_finding_archive_batch"),
        ),
        AddIndexConcurrently(
            model_name="jira_issue",
            index=models.Index(condition=models.Q(("archive_batch__isnull", False)), fields=["archive_batch"], name="dojo_jiraissue_archive_batch"),
        ),
        AddIndexConcurrently(
            model_name="locationfindingreference",
            index=models.Index(condition=models.Q(("archive_batch__isnull", False)), fields=["archive_batch"], name="dojo_locfindref_archive_batch"),
        ),
        AddIndexConcurrently(
            model_name="product",
            index=models.Index(condition=models.Q(("archive_batch__isnull", False)), fields=["archive_batch"], name="dojo_product_archive_batch"),
        ),
        AddIndexConcurrently(
            model_name="product_type",
            index=models.Index(condition=models.Q(("archive_batch__isnull", False)), fields=["archive_batch"], name="dojo_prod_type_archive_batch"),
        ),
        AddIndexConcurrently(
            model_name="test",
            index=models.Index(condition=models.Q(("archive_batch__isnull", False)), fields=["archive_batch"], name="dojo_test_archive_batch"),
        ),
        AddIndexConcurrently(
            model_name="test_import_finding_action",
            index=models.Index(condition=models.Q(("archive_batch__isnull", False)), fields=["archive_batch"], name="dojo_tifa_archive_batch"),
        ),
        AddIndexConcurrently(
            model_name="vulnerability_id",
            index=models.Index(condition=models.Q(("archive_batch__isnull", False)), fields=["archive_batch"], name="dojo_vulnid_archive_batch"),
        ),
    ]
