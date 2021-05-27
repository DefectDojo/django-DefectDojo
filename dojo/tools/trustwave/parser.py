import csv
import hashlib
import io

from dojo.models import Endpoint, Finding


class TrustwaveParser(object):

    def get_scan_types(self):
        return ["Trustwave Scan (CSV)"]

    def get_label_for_scan_types(self, scan_type):
        return "Trustwave Scan (CSV)"

    def get_description_for_scan_types(self, scan_type):
        return "CSV output of Trustwave vulnerability scan."

    def get_findings(self, filename, test):

        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        reader = csv.DictReader(io.StringIO(content), delimiter=',', quotechar='"')

        severity_mapping = {
            'I': 'Info',
            'L': 'Low',
            'M': 'Medium',
            'H': 'High',
            'C': 'Critical',
        }

        dupes = {}
        for row in reader:
            finding = Finding(
                test=test,
                nb_occurences=1,
            )
            host = row.get('Domain')
            if host is None or host == '':
                host = row.get('IP')
            finding.unsaved_endpoints = [Endpoint(host=host)]
            if row.get('Port') is not None and not "" == row.get('Port'):
                finding.unsaved_endpoints[0].port = int(row['Port'])
            if row.get('Protocol') is not None and not "" == row.get('Protocol'):
                finding.unsaved_endpoints[0].protocol = row['Protocol']
            finding.title = row['Vulnerability Name']
            finding.description = row['Description']
            finding.references = row.get('Evidence')
            finding.mitigation = row.get('Remediation')

            # manage severity
            if row['Severity'] in severity_mapping:
                finding.severity = severity_mapping[row['Severity']]
            else:
                finding.severity = 'Low'
            finding.cve = row.get('CVE')

            dupes_key = hashlib.sha256("|".join([
                finding.severity,
                finding.title,
                finding.description
            ]).encode()).hexdigest()

            if dupes_key in dupes:
                dupes[dupes_key].nb_occurences += 1
            else:
                dupes[dupes_key] = finding

        return list(dupes.values())
