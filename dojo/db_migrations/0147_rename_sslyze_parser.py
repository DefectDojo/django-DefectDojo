from django.db import migrations


def rename_sslyze_parser(apps, schema_editor):
    Test_Type_model = apps.get_model('dojo', 'Test_Type')
    try:
        test_type_sslyze = Test_Type_model.objects.get(name='SSLyze 3 Scan (JSON)')
        test_type_sslyze.name = 'SSLyze Scan (JSON)'
        test_type_sslyze.save()
    except Test_Type_model.DoesNotExist:
        # This happens when a new instance of DD is initialized
        pass


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0146_lead_optional'),
    ]

    operations = [
        migrations.RunPython(rename_sslyze_parser),
    ]
