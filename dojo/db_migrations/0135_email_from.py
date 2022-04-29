from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0134_sonarque_cobaltio_removal'),
    ]

    operations = [
        migrations.RenameField(
            model_name='system_settings',
            old_name='mail_notifications_from',
            new_name='email_from',
        ),
        migrations.AlterField(
            model_name='system_settings',
            name='email_from',
            field=models.CharField(blank=True, default='no-reply@example.com', max_length=200),  # change of defualt value
        ),
    ]
