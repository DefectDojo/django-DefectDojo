from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('dojo', '0160_remove_broken_endpoint_statuses'),
    ]

    operations = [
        migrations.CreateModel(
            name='SLA',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=300)),
                ('sla_critical', models.IntegerField(null=False)),
                ('sla_high', models.IntegerField(null=False)),
                ('sla_medium', models.IntegerField(null=False)),
                ('sla_low', models.IntegerField(null=False))
            ]
        ),
        migrations.CreateModel(
            name='Product SLA',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('dojo_product_id', models.IntegerField(null=False)),
                ('dojo_sla_id', models.IntegerField(null=False)),
            ]
        )
    ]
