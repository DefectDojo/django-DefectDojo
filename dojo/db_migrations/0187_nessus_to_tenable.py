from django.db import migrations
import logging

logger = logging.getLogger(__name__)


NESSUS_REFERENCES = ['Nessus Scan', 'Nessus WAS Scan']


# update the test type object as well as the scan type name
def update_test(test, tenable_test_type) -> None:
    if test.test_type.name in NESSUS_REFERENCES or test.scan_type in NESSUS_REFERENCES:
        test.test_type = tenable_test_type
        test.scan_type = tenable_test_type.name
        test.save()


# Update the found_by field to remove nessues/WAS and add tenable
def update_finding(finding, tenable_test_type, nessus_test_type, nessus_was_test_type) -> None:
    # Check if nessus is in found by list and remove
    if nessus_test_type in finding.found_by.all():
        finding.found_by.remove(nessus_test_type.id)
    # Check if nessus WAS is in found by list and remove
    if nessus_was_test_type in finding.found_by.all():
        finding.found_by.remove(nessus_was_test_type.id)
    # Check if tenable is already in list somehow before adding it
    if tenable_test_type not in finding.found_by.all():
        finding.found_by.add(tenable_test_type.id)
    finding.save()


# Update all finding objects that came from nessus/WAS reports
def migrate_nessus_findings_to_tenable(apps, schema_editor):
    finding_model = apps.get_model('dojo', 'Finding')
    test_type_model = apps.get_model('dojo', 'Test_Type')
    # Get or create Tenable Test Type and fetch the nessus and nessus WAS test types
    tenable_test_type, _ = test_type_model.objects.get_or_create(name="Tenable Scan", active=True)
    nessus_test_type = test_type_model.objects.filter(name="Nessus Scan").first()
    nessus_was_test_type = test_type_model.objects.filter(name="Nessus WAS Scan").first()
    # Get all the findings found by Nessus and Nessus WAS
    findings = finding_model.objects.filter(test__scan_type__in=NESSUS_REFERENCES)
    logger.warning(f'We identified {findings.count()} Nessus/NessusWAS findings to migrate to Tenable findings')
    # Iterate over all findings and change
    for finding in findings:
        # Update the found by field
        update_finding(finding, tenable_test_type, nessus_test_type, nessus_was_test_type)
        # Update the test object
        update_test(finding.test, tenable_test_type)


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0186_system_settings_non_common_password_required'),
    ]

    operations = [
        migrations.RunPython(migrate_nessus_findings_to_tenable),
    ]
