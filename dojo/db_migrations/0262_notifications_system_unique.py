from django.db import migrations, models


def deduplicate_system_notifications(apps, schema_editor):
    """Remove duplicate Notification rows where user and product are both NULL.

    Keeps the oldest row (lowest pk) for each template value and deletes the rest.
    """
    Notifications = apps.get_model("dojo", "Notifications")
    # Handle both template=True and template=False system notifications
    for template_val in [True, False]:
        dupes = (
            Notifications.objects
            .filter(user__isnull=True, product__isnull=True, template=template_val)
            .order_by("pk")
        )
        ids = list(dupes.values_list("pk", flat=True))
        if len(ids) > 1:
            # Keep the first, delete the rest
            Notifications.objects.filter(pk__in=ids[1:]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0261_remove_url_insert_insert_remove_url_update_update_and_more"),
    ]

    operations = [
        migrations.RunPython(
            deduplicate_system_notifications,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.AddConstraint(
            model_name="notifications",
            constraint=models.UniqueConstraint(
                condition=models.Q(user__isnull=True, product__isnull=True),
                fields=("template",),
                name="notifications_system_unique",
            ),
        ),
    ]
