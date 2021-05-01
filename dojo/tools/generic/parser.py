import csv
import hashlib
import io
import hyperlink

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

            # manage active/verified overrride
            if active:
                finding.active = active
            if verified:
                finding.verified = verified

            # manage endpoints
            if 'Url' in row:
                url = hyperlink.parse(row['Url'])
                endpoint = Endpoint(
                    protocol=url.scheme,
                    host=url.host + (":" + str(url.port)) if url.port is not None else "",
                    path="/".join(url.path),
                )
                if url.query:
                    endpoint.query = url.query
                if url.fragment:
                    endpoint.fragment = url.fragment
                finding.unsaved_endpoints = [endpoint]

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
