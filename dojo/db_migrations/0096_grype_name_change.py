from django.db import migrations


class Migration(migrations.Migration):
    def rename_grype_parser_name(apps, schema_editor):
        test_type_model = apps.get_model('dojo', 'Test_Type')

        # rename 'anchore_grype' to 'Anchore Grype'
        grype_testtype = test_type_model.objects.filter(name='anchore_grype').first()
        if grype_testtype:
            grype_testtype.name = 'Anchore Grype'
            grype_testtype.save()

    def reverse_rename_grype_parser_name(apps, schema_editor):
        test_type_model = apps.get_model('dojo', 'Test_Type')

        grype_testtype = test_type_model.objects.filter(name='Anchore Grype').first()
        if grype_testtype:
            grype_testtype.name = 'anchore_grype'
            grype_testtype.save()

    dependencies = [
        ('dojo', '0095_remove_old_product_contact_fields'),
    ]

    operations = [migrations.RunPython(rename_grype_parser_name, reverse_rename_grype_parser_name)]
