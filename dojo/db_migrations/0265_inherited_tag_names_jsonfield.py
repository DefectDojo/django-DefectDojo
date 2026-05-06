"""
Replace the duplicate `inherited_tags` TagField on Engagement / Test /
Finding / Endpoint / Location with a `_inherited_tag_names` JSONField.

Phase B Stage 3 of the tag inheritance redesign. Copies existing M2M data
into the JSON column, then drops the M2M field (which also drops the
auto-generated through tables and the Tagulous tag tables for the
inherited_tags side).
"""
from django.db import migrations, models


def copy_inherited_tags_to_json(apps, schema_editor):
    """Copy each child's inherited_tags M2M values into _inherited_tag_names JSON."""
    for app_label, model_name in [
        ("dojo", "Engagement"),
        ("dojo", "Test"),
        ("dojo", "Finding"),
        ("dojo", "Endpoint"),
        ("dojo", "Location"),
    ]:
        try:
            Model = apps.get_model(app_label, model_name)
        except LookupError:
            continue
        for obj in Model.objects.iterator(chunk_size=1000):
            try:
                names = sorted(obj.inherited_tags.values_list("name", flat=True))
            except Exception:
                names = []
            if names:
                Model.objects.filter(pk=obj.pk).update(_inherited_tag_names=names)


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0264_alter_url_identity_hash_alter_urlevent_identity_hash"),
    ]

    operations = [
        # 1. Add the JSON column to each child model.
        migrations.AddField(
            model_name="engagement",
            name="_inherited_tag_names",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="Internal: tag names inherited from the product, used to identify which entries in `tags` came from inheritance vs user input.",
            ),
        ),
        migrations.AddField(
            model_name="endpoint",
            name="_inherited_tag_names",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="Internal: tag names inherited from the product, used to identify which entries in `tags` came from inheritance vs user input.",
            ),
        ),
        migrations.AddField(
            model_name="test",
            name="_inherited_tag_names",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="Internal: tag names inherited from the product, used to identify which entries in `tags` came from inheritance vs user input.",
            ),
        ),
        migrations.AddField(
            model_name="finding",
            name="_inherited_tag_names",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="Internal: tag names inherited from the product, used to identify which entries in `tags` came from inheritance vs user input.",
            ),
        ),
        migrations.AddField(
            model_name="location",
            name="_inherited_tag_names",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="Internal: tag names inherited from the product, used to identify which entries in `tags` came from inheritance vs user input.",
            ),
        ),
        # 2. Copy existing M2M data into the JSON column.
        migrations.RunPython(copy_inherited_tags_to_json, migrations.RunPython.noop),
        # 3. Drop pghistory proxies and event-tracking tables for the
        #    inherited_tags through tables (created by migration 0256).
        #    Must precede the RemoveField below: Django's state-rendering
        #    fails to resolve the proxy bases once their through table
        #    target is gone.
        migrations.DeleteModel(name="EngagementInheritedTagsEvent"),
        migrations.DeleteModel(name="EndpointInheritedTagsEvent"),
        migrations.DeleteModel(name="TestInheritedTagsEvent"),
        migrations.DeleteModel(name="FindingInheritedTagsEvent"),
        migrations.DeleteModel(name="EngagementInheritedTags"),
        migrations.DeleteModel(name="EndpointInheritedTags"),
        migrations.DeleteModel(name="TestInheritedTags"),
        migrations.DeleteModel(name="FindingInheritedTags"),
        # 4. Drop the duplicate inherited_tags TagField on each child. Django
        #    will also drop the auto-generated `dojo_<model>_inherited_tags`
        #    through tables.
        migrations.RemoveField(model_name="engagement", name="inherited_tags"),
        migrations.RemoveField(model_name="endpoint", name="inherited_tags"),
        migrations.RemoveField(model_name="test", name="inherited_tags"),
        migrations.RemoveField(model_name="finding", name="inherited_tags"),
        migrations.RemoveField(model_name="location", name="inherited_tags"),
        # 5. Drop the now-orphaned Tagulous tag models that backed the
        #    `inherited_tags` TagFields. These were created in migration
        #    0188 (and 0259 for Location).
        migrations.DeleteModel(name="Tagulous_Engagement_inherited_tags"),
        migrations.DeleteModel(name="Tagulous_Endpoint_inherited_tags"),
        migrations.DeleteModel(name="Tagulous_Test_inherited_tags"),
        migrations.DeleteModel(name="Tagulous_Finding_inherited_tags"),
        migrations.DeleteModel(name="Tagulous_Location_inherited_tags"),
        # No GIN index added: the current code reads the JSON column per
        # row via `_sync_inheritance_for_qs` (Python-side diff) rather than
        # filtering with `_inherited_tag_names__contains`. Add a GIN index
        # in a follow-up if production query patterns shift toward SQL-side
        # containment lookups.
    ]
