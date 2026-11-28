from django.db import migrations, models

# Restated as literals because a migration must not read live code.
OLD_DESCRIPTION = "The Default SLA Configuration. Products not using an explicit SLA Configuration will use this one."
NEW_DESCRIPTION = "The Default SLA Configuration, used wherever no other SLA Configuration is assigned."
OLD_NO_SLA_DESCRIPTION = "No SLA is enforced for a product which uses this SLA configuration."
NEW_NO_SLA_DESCRIPTION = "No SLA is enforced for anything that uses this SLA configuration."
# (seeded text, relabel-neutral text): the two descriptions the sla_configurations fixture seeds.
REWRITES = ((OLD_DESCRIPTION, NEW_DESCRIPTION), (OLD_NO_SLA_DESCRIPTION, NEW_NO_SLA_DESCRIPTION))
UNIQUE_NAME = {"unique": "An entry with this name already exists."}


def rewrite_default_sla_description(apps, schema_editor):
    """
    Replace the seeded SLA descriptions, which said "Products" whatever the Asset relabel showed.

    Only a row that still holds the exact seeded text changes: a description anyone edited is theirs and stays.
    A queryset update on the historical model, so no save() side effect (an SLA recalculation) runs.
    """
    sla_configuration = apps.get_model("dojo", "SLA_Configuration")
    for old, new in REWRITES:
        sla_configuration.objects.filter(description=old).update(description=new)


def restore_default_sla_description(apps, schema_editor):
    sla_configuration = apps.get_model("dojo", "SLA_Configuration")
    for old, new in REWRITES:
        sla_configuration.objects.filter(description=new).update(description=old)


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0314_sla_configuration_day_bounds"),
    ]

    operations = [
        migrations.AlterField(
            model_name="product",
            name="name",
            field=models.CharField(error_messages=UNIQUE_NAME, max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name="product_type",
            name="name",
            field=models.CharField(error_messages=UNIQUE_NAME, max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name="product_typeevent",
            name="name",
            field=models.CharField(error_messages=UNIQUE_NAME, max_length=255),
        ),
        migrations.AlterField(
            model_name="productevent",
            name="name",
            field=models.CharField(error_messages=UNIQUE_NAME, max_length=255),
        ),
        migrations.RunPython(rewrite_default_sla_description, restore_default_sla_description),
    ]
