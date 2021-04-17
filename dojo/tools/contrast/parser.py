
import csv
import hashlib
import io
import sys
import datetime

from dojo.models import Endpoint, Finding


class ContrastParser(object):
    """Contrast Scanner CSV Report"""

    def get_scan_types(self):
        return ["Contrast Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "CSV Report"

    def get_findings(self, filename, test):
        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        csv.field_size_limit(int(sys.maxsize / 10))  # the request/resp are big
        reader = csv.DictReader(io.StringIO(content))
        dupes = dict()

        for row in reader:
            # Vulnerability Name,Vulnerability ID,Category,Rule Name,Severity,Status,Number of Events,First Seen,Last Seen,Application Name,Application ID,Application Code,CWE ID,Request Method,Request Port,Request Protocol,Request Version,Request URI,Request Qs,Request Body
            cwe = self.format_cwe(row.get('CWE ID'))
            title = row.get('Vulnerability Name')
            category = row.get('Category')
            description = self.format_description(row)
            severity = row.get('Severity')
            if severity == "Note":
                severity = "Info"
            date_raw = datetime.datetime.utcfromtimestamp(int(row.get('First Seen')) / 1000)
            finding = Finding(
                title=title.split(' from')[0],
                date=date_raw,
                cwe=cwe,
                test=test,
                description=description,
                severity=severity,
                dynamic_finding=True,
                static_finding=False,
                vuln_id_from_tool=row.get('Rule Name'),
                unique_id_from_tool=row.get('Vulnerability ID'),
                nb_occurences=1,
            )
            finding.unsaved_endpoints = []
            if row.get('Request URI'):
                endpoint = Endpoint(
                    host="0.0.0.0",
                    path=row.get('Request URI'),
                    protocol=row.get('Request Protocol'),
                )
                finding.unsaved_endpoints.append(endpoint)

            if row.get('Request Qs', '') != '' and row.get('Request Body', '') != '':
                finding.unsaved_req_resp = []
                finding.unsaved_req_resp.append({"req": row.get('Request Qs') + '\n' + row.get('Request Body'), "resp": ''})

            dupe_key = hashlib.sha256("|".join([
                finding.vuln_id_from_tool,
            ]).encode("utf-8")).digest()

            if dupe_key in dupes:
                dupes[dupe_key].description = dupes[dupe_key].description + "\n-----\n" + finding.description
                dupes[dupe_key].unsaved_endpoints.extend(finding.unsaved_endpoints)
                dupes[dupe_key].nb_occurences += finding.nb_occurences
                dupes[dupe_key].unique_id_from_tool = None  # there is no uniq finding now
            else:
                dupes[dupe_key] = finding

        return list(dupes.values())

    def format_description(self, row):
        description = "**Title:** " + str(row.get('Vulnerability Name')) + "\n"
        description = description + "**Request URI**: " + str(row.get('Request URI')) + "\n"
        description = description + "**Rule Name:** " + row.get('Rule Name') + "\n"
        description = description + "**Vulnerability ID:** " + row.get('Vulnerability ID') + "\n"
        description = description + "**Vulnerability Name:** " + row.get('Vulnerability Name') + "\n"
        description = description + "**Status:** " + row.get('Status') + "\n"
        return description

    def format_cwe(self, url):
        # Get the last path
        filename = url.rsplit('/', 1)[1]

        # Split out the . to get the CWE id
        filename = filename.split('.')[0]

        return int(filename)
