from django.db import migrations
from django.db.models import F


class Migration(migrations.Migration):
    def rename_cyclonedx_parser_vuln_uniq(apps, schema_editor):
        """
        1) rename test type to reflect changes in the parser
        2) switch vuln_id_from_tool and unique_id_from_tool in findings
        """
        # rename 'cyclonedx' to 'CycloneDX Scan'
        test_type_model = apps.get_model('dojo', 'Test_Type')
        cyclonedx_testtype = test_type_model.objects.filter(name='cyclonedx').first()
        if cyclonedx_testtype:
            cyclonedx_testtype.name = 'CycloneDX Scan'
            cyclonedx_testtype.save()

        finding_model = apps.get_model('dojo', 'Finding')

        # extra protection, only migrate for the findings that have a non-null unique_id_from_tool
        findings = finding_model.objects.filter(test__test_type=cyclonedx_testtype, unique_id_from_tool__isnull=False)

        # assign value from unique_id_from tool to vuln_id_from_tool
        findings.update(vuln_id_from_tool=F('unique_id_from_tool'))

        # reset unique_id_from_tool
        findings.update(unique_id_from_tool=None)

    def reverse_cyclonedx_parser_vuln_uniq(apps, schema_editor):
        test_type_model = apps.get_model('dojo', 'Test_Type')

        cyclonedx_testtype = test_type_model.objects.filter(name='CycloneDX Scan').first()
        if cyclonedx_testtype:
            cyclonedx_testtype.name = 'cyclonedx'
            cyclonedx_testtype.save()

        findings = finding_model.objects.filter(test__test_type=cyclonedx_testtype, vuln_id_from_tool__isnull=False)

        # assign value from vuln_id_from tool to unique_id_from_tool
        findings.update(unique_id_from_tool=F('vuln_id_from_tool'))

        # reset vuln_id_from_tool
        findings.update(vuln_id_from_tool=None)

    dependencies = [
        ('dojo', '0113_endpoint_protocol'),
    ]

    operations = [
        migrations.RunPython(rename_cyclonedx_parser_vuln_uniq, reverse_cyclonedx_parser_vuln_uniq)
    ]
