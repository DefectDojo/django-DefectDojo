from django.db import migrations
import logging


logger = logging.getLogger(__name__)


OPENVAS_REFERENCES = ['OpenVAS CSV', 'OpenVAS XML']
CLAIRKLAR_REFERENCES = ['Clair Klar Scan']


# update the test type object as well as the scan type name
def update_openvas_test(test, openvas_test_type) -> None:
    if test.test_type.name in OPENVAS_REFERENCES or test.scan_type in OPENVAS_REFERENCES:
        test.test_type = openvas_test_type
        test.scan_type = openvas_test_type.name
        test.save()


def update_clairklar_test(test, clairklar_test_type) -> None:
    if test.test_type.name in CLAIRKLAR_REFERENCES or test.scan_type in CLAIRKLAR_REFERENCES:
        test.test_type = clairklar_test_type
        test.scan_type = clairklar_test_type.name
        test.save()


# Update the found_by field to remove OpenVAS CSV/ OpenVAS XML and add OpenVAS Parser
def update_openvas_finding(finding, openvas_test_type, openvascsv_test_type, openvasxml_test_type) -> None:
    # Check if nessus is in found by list and remove
    if openvascsv_test_type in finding.found_by.all():
        finding.found_by.remove(openvascsv_test_type.id)
    # Check if nessus WAS is in found by list and remove
    if openvasxml_test_type in finding.found_by.all():
        finding.found_by.remove(openvasxml_test_type.id)
    # Check if tenable is already in list somehow before adding it
    if openvas_test_type not in finding.found_by.all():
        finding.found_by.add(openvas_test_type.id)
    finding.save()


# Update the found_by field to remove Clair Klar Scan and add Clair Scan
def update_clairklar_finding(finding, clair_test_type, clairklar_test_type) -> None:
    # Check if nessus is in found by list and remove
    if clairklar_test_type in finding.found_by.all():
        finding.found_by.remove(clairklar_test_type.id)
    # Check if tenable is already in list somehow before adding it
    if clair_test_type not in finding.found_by.all():
        finding.found_by.add(clair_test_type.id)
    finding.save()


# Update all finding objects that came from OpenVAS CSV /XML reports
def migrate_openvas_parsers(apps, schema_editor):
    finding_model = apps.get_model('dojo', 'Finding')
    test_type_model = apps.get_model('dojo', 'Test_Type')
    # Get or create OpenVAS Test Type and fetch the OpenVAS XML and OpenVAS CSV test types
    openvas_test_type, _ = test_type_model.objects.get_or_create(name="OpenVAS Parser", defaults={"active": True})
    openvascsv_test_type = test_type_model.objects.filter(name="OpenVAS CSV").first()
    openvasxml_test_type = test_type_model.objects.filter(name="OpenVAS XML").first()
    # Get all the findings found by Nessus and Nessus WAS
    findings = finding_model.objects.filter(test__scan_type__in=OPENVAS_REFERENCES)
    logger.warning(f'We identified {findings.count()} OpenVAS CSV/ OpenVAS XML findings to migrate to OpenVAS Parser findings')
    # Iterate over all findings and change
    for finding in findings:
        # Update the found by field
        update_openvas_finding(finding, openvas_test_type, openvascsv_test_type, openvasxml_test_type)
        # Update the test object
        update_openvas_test(finding.test, openvas_test_type)


# Update all finding objects that came from Clair Klar reports
def migrate_clairklar_parsers(apps, schema_editor):
    finding_model = apps.get_model('dojo', 'Finding')
    test_type_model = apps.get_model('dojo', 'Test_Type')
    # Get or create Clair Scan Test Type and fetch the Clair Klar Scan test types
    clair_test_type, _ = test_type_model.objects.get_or_create(name="Clair Scan", defaults={"active": True})
    clairklar_test_type = test_type_model.objects.filter(name="Clair Klar Scan").first()
    # Get all the findings found by Clair Klar Scan
    findings = finding_model.objects.filter(test__scan_type__in=CLAIRKLAR_REFERENCES)
    logger.warning(f'We identified {findings.count()} Clair Klar Scan findings to migrate to Clair Scan findings')
    # Iterate over all findings and change
    for finding in findings:
        # Update the found by field
        update_clairklar_finding(finding, clair_test_type, clairklar_test_type)
        # Update the test object
        update_clairklar_test(finding.test, clair_test_type)


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0196_notifications_sla_breach_combined'),
    ]

    operations = [
        migrations.RunPython(migrate_openvas_parsers),
        migrations.RunPython(migrate_clairklar_parsers),
    ]
