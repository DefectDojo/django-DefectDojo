import io
import csv
import json
import logging
import hashlib

from django.utils.html import escape
from dojo.models import Finding

logger = logging.getLogger(__name__)


class TwistlockCSVParser(object):

    def get_field_from_row_or_default(self, row, column, default_value):
        field = row[column]
        if field is None or field == '':
            return default_value
        return escape(field)

    def parse_issue(self, row, test):

        if not row:
            return None

        id_column = 4
        line_column = 5
        code_line_column = 6
        vulnerability_id_column = 10
        severity_column = 13
        package_name_column = 14
        package_version_column = 16
        cvss_column = 18
        fix_status_column = 19
        description_column = 20
        data_vulnerability_id = self.get_field_from_row_or_default(row, vulnerability_id_column, '')
        data_package_version = self.get_field_from_row_or_default(row, package_version_column, '')
        data_fix_status = self.get_field_from_row_or_default(row, fix_status_column, '')
        data_package_name = self.get_field_from_row_or_default(row, package_name_column, '')
        data_id = self.get_field_from_row_or_default(row, id_column, '')
        data_severity = self.get_field_from_row_or_default(row, severity_column, 'Info').capitalize()
        data_cvss = self.get_field_from_row_or_default(row, cvss_column, '')
        data_description = self.get_field_from_row_or_default(row, description_column, '')

        finding = Finding(
            title=data_vulnerability_id + ": " + data_package_name + " - " + data_package_version,
            cve=data_vulnerability_id,
            test=test,
            severity=data_severity,
            description=data_description + "<p> Vulnerable Package: " +
            data_package_name + "</p><p> Current Version: " + str(
                data_package_version) + "</p>",
            mitigation=data_fix_status,
            component_name=data_package_name,
            component_version=data_package_version,
            active=False,
            verified=False,
            false_p=False,
            duplicate=False,
            out_of_scope=False,
            mitigated=None,
            severity_justification="(CVSS v3 base score: {})".format(data_cvss),
            impact=data_severity)

        finding.description = finding.description.strip()

        return finding

    def parse(self, filename, test):
        if filename is None:
            self.items = ()
            return
        content = filename.read()
        dupes = dict()
        if type(content) is bytes:
            content = content.decode('utf-8')
        reader = csv.reader(io.StringIO(content), delimiter=',', quotechar='"')
        firstline = True
        for row in reader:
            if firstline:
                firstline = False
                continue
            finding = self.parse_issue(row, test)
            if finding is not None:
                key = hashlib.md5((finding.severity + '|' + finding.title + '|' + finding.description).encode('utf-8')).hexdigest()
                if key not in dupes:
                    dupes[key] = finding
        return list(dupes.values())


class TwistlockJsonParser(object):
    def parse(self, json_output, test):
        tree = self.parse_json(json_output)
        items = []
        if tree:
            items = [data for data in self.get_items(tree, test)]
        return items

    def parse_json(self, json_output):
        try:
            data = json_output.read()
            try:
                tree = json.loads(str(data, 'utf-8'))
            except:
                tree = json.loads(data)
        except:
            raise Exception("Invalid format")

        return tree

    def get_items(self, tree, test):
        items = {}
        if 'results' in tree:
            try:
                vulnerabilityTree = tree['results'][0]['vulnerabilities']

                for node in vulnerabilityTree:

                    item = get_item(node, test)
                    unique_key = node['id'] + str(node['packageName'] + str(
                        node['packageVersion']) + str(node['severity']))
                    items[unique_key] = item
            except KeyError as ke:
                logger.warn("Could not find key {}".format(ke))

        return list(items.values())


def get_item(vulnerability, test):
    # Following the CVSS Scoring per https://nvd.nist.gov/vuln-metrics/cvss
    if 'severity' in vulnerability:
        # If we're dealing with a license finding, there will be no cvssScore
        if vulnerability['severity'] == 'important':
            severity = "High"
        elif vulnerability['severity'] == 'moderate':
            severity = "Medium"
        else:
            severity = vulnerability['severity'].title()
    # TODO: some seem to not have anything. Needs UNKNOWN new status in the model. Some vuln do not yet have cvss assigned.
    else:
        severity = "Info"

    vector = vulnerability['vector'] if 'vector' in vulnerability else "CVSS vector not provided. "
    status = vulnerability['status'] if 'status' in vulnerability else "There seems to be no fix yet. Please check description field."
    cvss = vulnerability['cvss'] if 'cvss' in vulnerability else "No CVSS score yet."
    riskFactors = vulnerability['riskFactors'] if 'riskFactors' in vulnerability else "No risk factors."

    # create the finding object
    finding = Finding(
        title=vulnerability['id'] + ": " + vulnerability['packageName'] + " - " + vulnerability['packageVersion'],
        cve=vulnerability['id'],
        test=test,
        severity=severity,
        description=vulnerability['description'] + "<p> Vulnerable Package: " +
        vulnerability['packageName'] + "</p><p> Current Version: " + str(
            vulnerability['packageVersion']) + "</p>",
        mitigation=status.title(),
        references=vulnerability['link'],
        component_name=vulnerability['packageName'],
        component_version=vulnerability['packageVersion'],
        active=False,
        verified=False,
        false_p=False,
        duplicate=False,
        out_of_scope=False,
        mitigated=None,
        severity_justification="{} (CVSS v3 base score: {})\n\n{}".format(vector, cvss, riskFactors),
        impact=severity)

    finding.description = finding.description.strip()

    return finding


class TwistlockParser(object):

    def __init__(self, filename, test):
        self.dupes = dict()

        if filename is None:
            self.items = []
            return

        if filename.name.lower().endswith('.json'):
            self.items = TwistlockJsonParser().parse(filename, test)
        elif filename.name.lower().endswith('.csv'):
            self.items = TwistlockCSVParser().parse(filename, test)
        else:
            raise Exception('Unknown File Format')
