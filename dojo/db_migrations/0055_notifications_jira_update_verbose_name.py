from django.db import migrations, models
import multiselectfield.db.fields
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0054_dojometa_finding'),
    ]

    operations = [
        migrations.AlterField(
            model_name='notifications',
            name='jira_update',
            field=multiselectfield.db.fields.MultiSelectField(blank=True, choices=[('slack', 'slack'), ('hipchat', 'hipchat'), ('mail', 'mail'), ('alert', 'alert')], default='alert', help_text='JIRA sync happens in the background, errors will be shown as notifications/alerts so make sure to subscribe', max_length=24, verbose_name='JIRA problems'),
        ),
        migrations.AlterField(
            model_name='alerts',
            name='title',
            field=models.CharField(default='', max_length=200),
        ),
        migrations.AlterField(
            model_name='jira_pkey',
            name='conf',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='dojo.JIRA_Conf', verbose_name='JIRA Configuration'),
        ),
        migrations.AlterField(
            model_name='jira_pkey',
            name='product',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dojo.Product'),
        ),

    ]
