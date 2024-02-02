from django.db import migrations
import logging


logger = logging.getLogger(__name__)


VERACODESOURCECLEAR_REFERENCES = ['Veracode SourceClear Scan']

def update_veracodesourceclear_test(test, veracodesourceclear_test_type) -> None:
    if test.test_type.name in VERACODESOURCECLEAR_REFERENCES or test.scan_type in VERACODESOURCECLEAR_REFERENCES:
        test.test_type = veracodesourceclear_test_type
        test.scan_type = veracodesourceclear_test_type.name
        test.save()

# Update the found_by field to remove Veracode SourceClear Scan and add Veracode Scan
def update_veracodesourceclear_finding(finding, veracode_test_type, veracodesourceclear_test_type) -> None:
    # Check if nessus is in found by list and remove
    if veracodesourceclear_test_type in finding.found_by.all():
        finding.found_by.remove(veracodesourceclear_test_type.id)
    # Check if tenable is already in list somehow before adding it
    if veracode_test_type not in finding.found_by.all():
        finding.found_by.add(veracode_test_type.id)
    finding.save()


# Update all finding objects that came from Veracode SourceClear reports
def migrate_veracode_parsers(apps, schema_editor):
    finding_model = apps.get_model('dojo', 'Finding')
    test_type_model = apps.get_model('dojo', 'Test_Type')
    # Get or create Veracode Scan Test Type and fetch the Veracode SourceClear Scan test types
    veracode_test_type, _ = test_type_model.objects.get_or_create(name="Veracode Scan", active=True)
    veracodesourceclear_test_type = test_type_model.objects.filter(name="Veracode SourceClear Scan").first()
    # Get all the findings found by Veracode SourceClear Scan
    findings = finding_model.objects.filter(test__scan_type__in=VERACODESOURCECLEAR_REFERENCES)
    logger.warning(f'We identified {findings.count()} Veracode SourceClear Scan findings to migrate to Veracode Scan findings')
    # Iterate over all findings and change
    for finding in findings:
        # Update the found by field
        update_veracodesourceclear_finding(finding, veracode_test_type, veracodesourceclear_test_type)
        # Update the test object
        update_veracodesourceclear_test(finding.test, veracode_test_type)


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0199_whitesource_to_mend'),
    ]

    operations = [
        migrations.RunPython(migrate_veracode_parsers),
    ]
