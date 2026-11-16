from django.db import migrations, models

import dojo.product.numbering


class Migration(migrations.Migration):
    dependencies = [
        ("dojo", "0309_jira_project_suppress_sla_notification_comments"),
    ]

    operations = [
        migrations.AddField(
            model_name="product",
            name="engagement_number_format",
            field=models.CharField(blank=True, default="", help_text="Optional engagement number format, for example ENG-{number:04d}.", max_length=64, validators=[dojo.product.numbering.validate_engagement_number_format]),
        ),
        migrations.AddField(
            model_name="product",
            name="engagement_number_counter",
            field=models.PositiveIntegerField(default=0, editable=False),
        ),
        migrations.AddField(
            model_name="engagement",
            name="engagement_number",
            field=models.CharField(blank=True, editable=False, max_length=80, null=True),
        ),
        migrations.AddConstraint(
            model_name="engagement",
            constraint=models.UniqueConstraint(fields=("product", "engagement_number"), name="dojo_engagement_product_number_uniq"),
        ),
    ]
