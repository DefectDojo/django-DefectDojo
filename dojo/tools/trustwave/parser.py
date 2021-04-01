# Based on CSV, but rewrote because
# values in different columns required concatinaton

import csv
import hashlib
import io

from dojo.models import Endpoint, Finding

MAPPINGS = {"title": "Vulnerability Name",
            'description': 'Description',
            'port': 'Port',
            'references': 'Evidence',
            'mitigation': 'Remediation',
            'cve': 'CVE',
            'fqdn': 'Domain',
            'severity': 'Severity',
            'ip': 'IP'
            }


class Severityfilter():
    def __init__(self):
        self.severity_mapping = {'I': 'Info',
                                 'L': 'Low',
                                 'M': 'Medium',
                                 'H': 'High',
                                 'C': 'Critical'
                                 }
        self.severity = None

    def eval_column(self, column_value):
        if column_value in list(self.severity_mapping.keys()):
            self.severity = self.severity_mapping[column_value]
        else:
            self.severity = 'Info'


class TrustwaveParser(object):

    def get_scan_types(self):
        return ["Trustwave Scan (CSV)"]

    def get_label_for_scan_types(self, scan_type):
        return "Trustwave Scan (CSV)"

    def get_description_for_scan_types(self, scan_type):
        return "CSV output of Trustwave vulnerability scan."

    def get_findings(self, filename, test):
        self.dupes = dict()
        self.items = ()

        if filename is None:
            self.items = ()
            return

        content = filename.read()
        reader = csv.DictReader(io.StringIO(content), delimiter=',', quotechar='"')
        csvarray = []

        for row in reader:
            csvarray.append(row)

        for row in csvarray:
            finding = Finding(test=test)
            findingdict = {}
            endpointdict = {}
            referencesarray = []

            for field, column_name in list(MAPPINGS.items()):
                if column_name == 'IP':
                    endpointdict['host'] = row[column_name]
                    findingdict['url'] = row[column_name]
                elif column_name == 'Severity':
                    severityfilter = Severityfilter()
                    severityfilter.eval_column(row[column_name])
                    findingdict['severity'] = severityfilter.severity
                elif column_name == 'Port':
                    endpointdict[field] = int(row[column_name])
                elif column_name == 'CVE':
                    findingdict[field] = row[column_name]
                    referencesarray.append(row[column_name])
                elif column_name in ['Evidence']:
                    referencesarray.append(row[column_name])
                else:
                    if column_name in list(row.keys()):
                        findingdict[field] = row[column_name]

            finding.unsaved_endpoints = [Endpoint(
                host=endpointdict['host'],
                port=endpointdict['port']
            )]
            finding.title = findingdict['title']
            finding.description = findingdict['description']
            finding.references = "\n".join(referencesarray)
            finding.mitigation = findingdict['mitigation']
            finding.fqdn = findingdict['fqdn']
            finding.severity = findingdict['severity']
            finding.url = findingdict['url']
            finding.cve = findingdict.get('cve')

            if finding is not None:
                if finding.url is None:
                    finding.url = ""
                if finding.title is None:
                    finding.title = ""
                if finding.description is None:
                    finding.description = ""

                key = hashlib.sha256("|".join([
                    finding.url,
                    finding.severity,
                    finding.title,
                    finding.description
                ]).encode()).hexdigest()

                if key not in self.dupes:
                    self.dupes[key] = finding

        return list(self.dupes.values())
