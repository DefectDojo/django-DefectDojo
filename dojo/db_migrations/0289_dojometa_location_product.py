import django.db.models.deletion
from django.db import migrations, models

BATCH_SIZE = 1000


def scope_location_meta_to_products(apps, schema_editor):
    """
    Give every existing Location metadata row a product.

    An existing row has no single owner, because a Location is shared by every product that
    references it. Copying it to each of them keeps what every product could already see,
    at the cost of one row per product from here on.
    """
    DojoMeta = apps.get_model("dojo", "DojoMeta")
    LocationProductReference = apps.get_model("dojo", "LocationProductReference")
    copies = []
    for meta in DojoMeta.objects.filter(
        location__isnull=False, location_product__isnull=True,
    ).iterator(chunk_size=BATCH_SIZE):
        product_ids = list(
            LocationProductReference.objects.filter(location_id=meta.location_id)
            .values_list("product_id", flat=True),
        )
        if not product_ids:
            continue
        meta.location_product_id = product_ids[0]
        meta.save(update_fields=["location_product"])
        copies.extend(
            DojoMeta(
                location_id=meta.location_id,
                location_product_id=product_id,
                name=meta.name,
                value=meta.value,
            )
            for product_id in product_ids[1:]
        )
        if len(copies) >= BATCH_SIZE:
            DojoMeta.objects.bulk_create(copies, batch_size=BATCH_SIZE, ignore_conflicts=True)
            copies = []
    if copies:
        DojoMeta.objects.bulk_create(copies, batch_size=BATCH_SIZE, ignore_conflicts=True)


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0288_backfill_vulnerability_id_entities"),
    ]

    operations = [
        migrations.AddField(
            model_name="dojometa",
            name="location_product",
            field=models.ForeignKey(
                editable=False,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="location_meta_scope",
                to="dojo.product",
            ),
        ),
        migrations.AlterUniqueTogether(
            name="dojometa",
            unique_together={
                ("product", "name"),
                ("endpoint", "name"),
                ("finding", "name"),
                ("location", "location_product", "name"),
            },
        ),
        migrations.RunPython(scope_location_meta_to_products, migrations.RunPython.noop),
    ]
