from django.db import migrations
import logging

logger = logging.getLogger(__name__)


WHITESOURCE_REFERENCES = ['Whitesource Scan']


# update the test type object as well as the scan type name
def update_test(test, mend_test_type) -> None:
    if test.test_type.name in WHITESOURCE_REFERENCES or test.scan_type in WHITESOURCE_REFERENCES:
        test.test_type = mend_test_type
        test.scan_type = mend_test_type.name
        test.save()


# Update the found_by field to remove whitesource and add mend
def update_finding(finding, mend_test_type, whitesource_test_type) -> None:
    # Check if whitesource is in found by list and remove
    if whitesource_test_type in finding.found_by.all():
        finding.found_by.remove(whitesource_test_type.id)
    # Check if whitesource is in found by list and remove
    if whitesource_test_type in finding.found_by.all():
        finding.found_by.remove(whitesource_test_type.id)
    # Check if mend is already in list somehow before adding it
    if mend_test_type not in finding.found_by.all():
        finding.found_by.add(mend_test_type.id)
    finding.save()


# Update all finding objects that came from whitesource reports
def migrate_whitesource_findings_to_mend(apps, schema_editor):
    finding_model = apps.get_model('dojo', 'Finding')
    test_type_model = apps.get_model('dojo', 'Test_Type')
    # Get or create Mend Test Type and fetch the whitesource test types
    mend_test_type, _ = test_type_model.objects.get_or_create(name="Mend Scan", defaults={"active": True})
    whitesource_test_type = test_type_model.objects.filter(name="Whitesource Scan").first()
    # Get all the findings found by whitesource
    findings = finding_model.objects.filter(test__scan_type__in=WHITESOURCE_REFERENCES)
    logger.warning(f'We identified {findings.count()} Whitesource findings to migrate to Mend findings')
    # Iterate over all findings and change
    for finding in findings:
        # Update the found by field
        update_finding(finding, mend_test_type, whitesource_test_type)
        # Update the test object
        update_test(finding.test, mend_test_type)


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0198_alter_system_settings_enable_deduplication'),
    ]

    operations = [
        migrations.RunPython(migrate_whitesource_findings_to_mend),
    ]
