import csv
import hashlib
import io

from dojo.models import Endpoint, Finding


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

        dupes = dict()
        for row in reader:
            # filter 'OK'
            # possible values: LOW|MEDIUM|HIGH|CRITICAL + WARN|OK|INFO
            if row['severity'] in ['OK']:
                continue
            # convert severity
            severity = row['severity'].lower().capitalize()
            if severity == 'Warn':
                severity = 'Info'
            # detect CVEs
            cves = row['cve'].split(' ')
            if len(cves) == 0:
                cves = [None]

            for cve in cves:
                finding = Finding(
                    title=row['id'],
                    description=row['finding'],
                    severity=severity,
                    nb_occurences=1,
                )
                # manage CVE
                if cve:
                    finding.cve = cve
                    finding.references = '* [{0}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={0})'.format(cve)
                # manage CWE
                if '-' in row['cwe']:
                    finding.cwe = int(row['cwe'].split('-')[1].strip())
                # manage endpoint
                finding.unsaved_endpoints = [Endpoint(host=row['fqdn/ip'].split("/")[0])]
                if row.get('port') and row['port'].isdigit():
                    finding.unsaved_endpoints[0].port = int(row['port'])

                # internal de-duplication
                dupe_key = hashlib.sha256("|".join([
                    finding.description,
                    finding.title,
                    str(finding.cve)
                ]).encode('utf-8')).hexdigest()
                if dupe_key in dupes:
                    dupes[dupe_key].unsaved_endpoints.extend(finding.unsaved_endpoints)
                    dupes[dupe_key].nb_occurences += finding.nb_occurences
                else:
                    dupes[dupe_key] = finding

        return list(dupes.values())
