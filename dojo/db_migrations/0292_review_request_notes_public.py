from django.db import migrations

# The entry prefix written by request_finding_review since the feature was
# introduced. Matching on it (together with private=True) is the only way to
# identify historical review-request notes: the row carries no other marker.
REVIEW_REQUEST_PREFIX = "Review Request: "


def make_review_request_notes_public(apps, schema_editor):
    """
    Review-request notes used to be saved with private=True, which hid the
    reviewer instructions from the assigned reviewers themselves (private
    notes are visible to their author and superusers only). The view no
    longer stores them private; this flips the rows it already wrote.
    """
    Notes = apps.get_model("dojo", "Notes")
    Notes.objects.filter(private=True, entry__startswith=REVIEW_REQUEST_PREFIX).update(private=False)


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0291_dojometa_location_product"),
    ]

    operations = [
        migrations.RunPython(make_review_request_notes_public, migrations.RunPython.noop),
    ]
