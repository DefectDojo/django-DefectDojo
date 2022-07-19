import json
import re

from os.path import join

from django.urls import reverse
from dojo.models import FileUpload, Finding, Notes
from dojo.notifications.helper import create_notification
from jsonschema import ValidationError, validate
from uuid import uuid4


class CsafParser(object):
    """CSAF Scanner JSON Report"""

    def get_scan_types(self):
        return ["CSAF Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "CSAF Scan"

    def get_description_for_scan_types(self, scan_type):
        return "CSAF JSON report format"

    # file: django.core.files.uploadedfile.TemporaryUploadedFile
    def get_findings(self, file, dd_test):
        if file is None:
            raise Exception("No report file provided")

        csaf = json.load(file)

        # Raises on validation error.
        csaf_validate(dd_test, csaf)

        return csaf_import(dd_test, file, csaf)


def csaf_validate(dd_test, csaf):
    # https://github.com/oasis-tcs/csaf/raw/master/csaf_2.0/json_schema/csaf_json_schema.json
    schema_path = join('dojo', 'tools', 'csaf', 'csaf_json_schema.json')
    with open(schema_path, encoding="utf8") as csaf_schema_file:
        csaf_schema_json = json.load(csaf_schema_file)

    try:
        validate(csaf, schema=csaf_schema_json)
    except ValidationError as e:
        # `validate` raises on validation errors with a huge error
        # message complaining about the exact position of the validation
        # error.
        # The first line of said message is a summary, so we just
        # re`raise` using this line.
        reason = repr(e)

        create_notification(event='other',
                            title=reason,
                            description=e,
                            test=dd_test,
                            engagement=dd_test.engagement,
                            product=dd_test.engagement.product,
                            url=reverse('alerts'))

        raise ValidationError(reason)


def csaf_import(dd_test, file, json):
    document = json.get('document', {})
    vulnerabilities = json.get('vulnerabilities', {})
    product_tree = json.get('product_tree', {})

    engagement_title = document.get('title', '(No Title)')

    if hasattr(dd_test, 'engagement'):
        dd_test.engagement.name = engagement_title

        if 'notes' in document:
            dd_test.engagement.description = description_from_notes(document['notes'])

    # Defect Dojo does not allow file name duplications
    file_title = str(uuid4()) + '_' + file.name
    file_upload = FileUpload(title=file_title, file=file)
    file_upload.save()
    dd_test.files.add(file_upload)

    if 'publisher' in document:
        dd_test.notes.add(notes_from_publishers(dd_test, document['publisher']))

    out = []
    for vulnerability in vulnerabilities:
        # Default values
        args = {
            'severity': 'Info',
            'title': engagement_title,  # '(No Title)',
        }

        if 'cve' in vulnerability:
            args['cve'] = vulnerability['cve']

        cwe = vulnerability.get('cwe', {})
        if 'id' in cwe:
            opt_match = next(re.finditer(r'\d+', cwe['id']), None)
            if opt_match is not None:
                args['cwe'] = int(opt_match.group())

        if 'title' in vulnerability:
            args['title'] = vulnerability['title']

        if 'discovery_date' in vulnerability:
            args['date'] = vulnerability['discovery_date'][0:10]

        if 'url' in vulnerability:
            args['url'] = vulnerability['url']

        for score in vulnerability.get('scores', []):
            if 'cvss_v3' in score:
                cvssv3 = score['cvss_v3']
                if 'vectorString' in cvssv3:
                    args['cvssv3'] = cvssv3['vectorString']
                if 'baseScore' in cvssv3:
                    args['cvssv3_score'] = cvssv3['baseScore']
                if 'baseSeverity' in cvssv3:
                    args['severity'] = cvssv3['baseSeverity'].capitalize()
                break

        if 'notes' in vulnerability:
            args['description'] = description_from_notes(vulnerability['notes'])

        references = []
        for reference in document.get('references', []):
            if 'summary' in reference and 'url' in reference:
                url = reference['url']
                summary = reference['summary']
                references.append(f'* {summary}: {url}')
        args['references'] = '\n'.join(references)

        remediations = []
        for remediation in vulnerability.get('remediations', []):
            if 'details' in remediation:
                remediations.append(remediation['details'].replace('\n', ''))
        args['mitigation'] = '\n'.join(remediations)

        out.append(Finding(**args))

    return out


def description_from_notes(notes):
    descriptions = []

    # Descriptions are the short version of summaries
    for note in notes:
        if note['category'] == 'description' and 'text' in note:
            descriptions.insert(0, note['text'].replace('\n', ''))
        if note['category'] == 'summary' and 'text' in note:
            descriptions.append(note['text'].replace('\n', ''))

    return '\n\n'.join(descriptions)


def notes_from_publishers(dd_test, publishers):
    entry = '\n'.join(
        f'{field.replace("_", " ").title()}: {publishers[field]}' for field in publishers
    )

    notes = Notes(entry=entry, author=dd_test.lead)
    notes.save()

    return notes
