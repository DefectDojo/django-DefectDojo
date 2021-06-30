import json
import re
import datetime

from dojo.models import Finding, Endpoint

# Function to remove HTML tags
TAG_RE = re.compile(r'<[^>]+>')


def cleantags(text=''):
    prepared_text = text if text else ''
    return TAG_RE.sub('', prepared_text)


class Acunetix360Parser(object):

    def get_scan_types(self):
        return ["Acunetix360 Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Acunetix360 Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Acunetix360 JSON format."

    def get_findings(self, filename, test):
        data = json.load(filename)
        dupes = dict()

        for item in data["Vulnerabilities"]:
            title = item["Name"]
            findingdetail = cleantags(item["Description"])
            cwe = int(item["Classification"]["Cwe"]) if "Cwe" in item["Classification"] else None
            sev = item["Severity"]
            if sev not in ['Info', 'Low', 'Medium', 'High', 'Critical']:
                sev = 'Info'
            mitigation = cleantags(item["RemedialProcedure"])
            references = cleantags(item["RemedyReferences"])
            url = item["Url"]
            impact = cleantags(item["Impact"])
            dupe_key = title
            request = item["HttpRequest"]["Content"]
            if request is None or request.lenght <= 0:
                request = "Request Not Found"
            response = item["HttpResponse"]["Content"]
            if response is None or response.length <= 0:
                response = "Response Not Found"
            scan_date = datetime.datetime.strptime(item["Generated"], "%Y-%m-%dT%H:%M:%SZ").date()

            finding = Finding(title=title,
                              test=test,
                              description=findingdetail,
                              severity=sev.title(),
                              mitigation=mitigation,
                              impact=impact,
                              date=scan_date,
                              references=references,
                              cwe=cwe,
                              static_finding=True)

            if (item["Classification"] is not None) and (item["Classification"]["Cvss"] is not None) and (item["Classification"]["Cvss"]["Vector"] is not None):
                finding.cvssv3 = item["Classification"]["Cvss"]["Vector"]

            finding.unsaved_req_resp = [{"req": request, "resp": response}]
            finding.unsaved_endpoints = [Endpoint.from_uri(url)]

            if dupe_key in dupes:
                find = dupes[dupe_key]
                find.unsaved_req_resp.extend(finding.unsaved_req_resp)
                find.unsaved_endpoints.extend(finding.unsaved_endpoints)
            else:
                dupes[dupe_key] = finding

        return list(dupes.values())
