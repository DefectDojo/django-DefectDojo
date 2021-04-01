import csv
import hashlib
import io
import re

from dojo.models import Endpoint, Finding

__author__ = 'dr3dd589'

SEV = ['INFO', 'LOW', 'HIGH', 'WARN']


class TestsslParser(object):

    def get_scan_types(self):
        return ["Testssl Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Testssl Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import CSV output of testssl scan report."

    def get_findings(self, filename, test):
        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        reader = csv.DictReader(io.StringIO(content), delimiter=',', quotechar='"')
        csvarray = []

        for row in reader:
            csvarray.append(row)
        dupes = dict()
        for row in csvarray:
            if row['severity'] in SEV:
                host = row['fqdn/ip'].split('/')[0]
                port = int(row['port'])
                title = row['id']
                severity = row['severity'].lower().capitalize()
                if severity == 'Warn':
                    severity = 'Info'
                cves = row['cve'].split(' ')
                description = "**Finding** : " + row['finding'] + "\n\n"
                if len(cves) > 1:
                    cve_desc = ""
                    cve = cves[0]
                    for cve_ in cves:
                        cve_desc += '[{0}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={0})'.format(cve_) + ", "

                    description += "**Releted CVE's** : " + cve_desc[:-2]
                else:
                    try:
                        cve = cves[0]
                    except:
                        cve = None
                try:
                    cwe = re.findall(r'\d+', row['cwe'])[0]
                except:
                    cwe = None
                if title and description is not None:
                    dupe_key = hashlib.md5(str(description + title).encode('utf-8')).hexdigest()
                    if dupe_key in dupes:
                        finding = dupes[dupe_key]
                        self.process_endpoints(finding, host, port)
                        dupes[dupe_key] = finding
                    else:
                        dupes[dupe_key] = True

                        finding = Finding(
                            title=title,
                            test=test,
                            active=False,
                            verified=False,
                            description=description,
                            severity=severity,
                            cve=cve,
                            cwe=cwe,
                            numerical_severity=Finding.get_numerical_severity(severity))
                        finding.unsaved_endpoints = list()
                        dupes[dupe_key] = finding
                        self.process_endpoints(finding, host, port)
        return dupes.values()

    def process_endpoints(self, finding, host, port):
        endpoint = Endpoint.objects.get_or_create(
            host=host,
            port=port
        )
        if endpoint not in finding.unsaved_endpoints:
            finding.unsaved_endpoints.append(endpoint)