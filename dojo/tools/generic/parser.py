import csv
import hashlib
import io
import json

from dateutil.parser import parse
from dojo.models import Endpoint, Finding


class GenericParser(object):

    def get_scan_types(self):
        return ["Generic Findings Import"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import Generic findings in CSV format."

    def get_findings(self, filename, test, active=None, verified=None):
        if filename.name.lower().endswith(".csv"):
            return self.get_findings_csv(filename, test, active, verified)
        elif filename.name.lower().endswith(".json"):
            return self.get_findings_json(filename, test, active, verified)
        else:  # default to CSV like before
            return self.get_findings_csv(filename, test, active, verified)

    def get_findings_json(self, filename, test, active=None, verified=None):
        data = json.load(filename)
        findings = list()
        for item in data['findings']:
            # remove endpoints of the dictionnary
            unsaved_endpoints = None
            if "endpoints" in item:
                unsaved_endpoints = item["endpoints"]
                del item["endpoints"]
            # remove files of the dictionnary
            unsaved_files = None
            if "files" in item:
                unsaved_files = item["files"]
                del item["files"]

            finding = Finding(**item)
            # manage active/verified overrride
            if active is not None:
                finding.active = active
            if verified is not None:
                finding.verified = verified

            # manage endpoints
            if unsaved_endpoints:
                finding.unsaved_endpoints = []
                for endpoint_item in unsaved_endpoints:
                    if type(endpoint_item) is str:
                        if '://' in endpoint_item:  # is the host full uri?
                            endpoint = Endpoint.from_uri(endpoint_item)
                            # can raise exception if the host is not valid URL
                        else:
                            endpoint = Endpoint.from_uri('//' + endpoint_item)
                            # can raise exception if there is no way to parse the host
                    else:
                        endpoint = Endpoint(**endpoint_item)
                    finding.unsaved_endpoints.append(endpoint)

            if unsaved_files:
                finding.unsaved_files = unsaved_files
            findings.append(finding)
        return findings

    def get_findings_csv(self, filename, test, active=None, verified=None):
        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        reader = csv.DictReader(io.StringIO(content), delimiter=',', quotechar='"')

        dupes = dict()
        for row in reader:
            finding = Finding(
                test=test,
                title=row['Title'],
                description=row['Description'],
                date=parse(row['Date']).date(),
                severity=row['Severity'],
                duplicate=self._convert_bool(row.get('Duplicate', 'FALSE')),  # bool False by default
                nb_occurences=1,
            )
            # manage active
            if 'Active' in row:
                finding.active = self._convert_bool(row.get('Active', 'FALSE'))  # bool False by default
            # manage mitigation
            if 'Mitigation' in row:
                finding.mitigation = row['Mitigation']
            # manage impact
            if 'Impact' in row:
                finding.impact = row['Impact']
            # manage impact
            if 'References' in row:
                finding.references = row['References']
            # manage verified
            if 'Verified' in row:
                finding.verified = self._convert_bool(row.get('Verified', 'FALSE'))  # bool False by default
            # manage false positives
            if 'FalsePositive' in row:
                finding.false_p = self._convert_bool(row.get('FalsePositive', 'FALSE'))  # bool False by default
            # manage CVE
            if 'CVE' in row:
                finding.cve = row['CVE']
            # manage CWE
            if 'CweId' in row:
                finding.cwe = int(row['CweId'])
            # FIXME remove this severity hack
            if finding.severity == 'Unknown':
                finding.severity = 'Info'

            if "CVSSV3" in row:
                finding.cvssv3 = row["CVSSV3"]

            # manage active/verified overrride
            if active:
                finding.active = active
            if verified:
                finding.verified = verified

            # manage endpoints
            if 'Url' in row:
                finding.unsaved_endpoints = [Endpoint.from_uri(row['Url'])
                                             if '://' in row['Url'] else
                                             Endpoint.from_uri("//" + row['Url'])]

            # manage internal de-duplication
            key = hashlib.sha256("|".join([
                finding.severity,
                finding.title,
                finding.description,
            ]).encode("utf-8")).hexdigest()
            if key in dupes:
                find = dupes[key]
                find.unsaved_endpoints.extend(finding.unsaved_endpoints)
                find.nb_occurences += 1
            else:
                dupes[key] = finding

        return list(dupes.values())

    def _convert_bool(self, val):
        return val.lower()[0:1] == 't'  # bool False by default
