from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0292_review_request_notes_public'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='usercontactinfo',
            name='ui_use_tailwind',
        ),
    ]
