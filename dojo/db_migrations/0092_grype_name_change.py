from django.db import migrations


class Migration(migrations.Migration):
    def rename_grype_parser_name(apps, schema_editor):
        test_type_model = apps.get_model('dojo', 'Test_Type')

        # rename 'anchore_grype' to 'Anchore Grype'
        grype_testtype = test_type_model.objects.all().filter(name='anchore_grype').first()
        grype_testtype.name = 'Anchore Grype'
        grype_testtype.save()

    dependencies = [
        ('dojo', '0091_npm_audit_path_censoring'),
    ]

    operations = [migrations.RunPython(rename_grype_parser_name)]
