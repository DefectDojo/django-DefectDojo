from django.db import migrations

class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0241_generalsettings_finding_ia_recommendation'),
        ('sessions', '0001_initial'),
    ]

    operations = [
        migrations.RunSQL("DELETE FROM django_session WHERE expire_date < NOW();"),
    ]
