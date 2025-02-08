from django.db import migrations
import logging


logger = logging.getLogger(__name__)


PARSER_REFERENCES = ['Acunetix360 Scan']


def update_parser_test(test, parser_test_type) -> None:
    if test.test_type.name in PARSER_REFERENCES or test.scan_type in PARSER_REFERENCES:
        test.test_type = parser_test_type
        test.scan_type = parser_test_type.name
        test.save()


# Update the found_by field to remove Acunetix360 and add Acunetix
def update_parser_finding(finding, newparser_test_type, parser_test_type) -> None:
    # Check if nessus is in found by list and remove
    if parser_test_type in finding.found_by.all():
        finding.found_by.remove(parser_test_type.id)
    # Check if tenable is already in list somehow before adding it
    if newparser_test_type not in finding.found_by.all():
        finding.found_by.add(newparser_test_type.id)
    finding.save()


# Update all finding objects that came from Acunetix360 reports
def forward_merge_parser(apps, schema_editor):
    finding_model = apps.get_model('dojo', 'Finding')
    test_type_model = apps.get_model('dojo', 'Test_Type')
    # Get or create Acunetix Scan Test Type and fetch the Acunetix360 Scan test types
    newparser_test_type, _ = test_type_model.objects.get_or_create(name="Acunetix Scan", defaults={"active": True})
    parser_test_type = test_type_model.objects.filter(name="Acunetix360 Scan").first()
    # Get all the findings found by Acunetix360 Scan
    findings = finding_model.objects.filter(test__scan_type__in=PARSER_REFERENCES)
    logger.warning(f'We identified {findings.count()} Acunetix360 Scan findings to migrate to Acunetix Scan findings')
    # Iterate over all findings and change
    for finding in findings:
        # Update the found by field
        update_parser_finding(finding, newparser_test_type, parser_test_type)
        # Update the test object
        update_parser_test(finding.test, newparser_test_type)


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0207_alter_sonarqube_issue_key'),
    ]

    operations = [
        migrations.RunPython(forward_merge_parser),
    ]
