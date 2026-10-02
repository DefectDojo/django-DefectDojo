from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0289_fileupload_title_not_unique'),
    ]

    operations = [
        migrations.AlterField(
            model_name='notes',
            name='private',
            field=models.BooleanField(default=False, help_text='Only you and superusers can see this note. It is also left out of reports and issue-tracker sync.'),
        ),
    ]
