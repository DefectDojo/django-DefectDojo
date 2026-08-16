from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0291_dojometa_location_product'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='usercontactinfo',
            name='ui_use_tailwind',
        ),
    ]
