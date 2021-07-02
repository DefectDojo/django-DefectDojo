import json
import datetime
import html2text

from dojo.models import Finding, Endpoint


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
        scan_date = datetime.datetime.strptime(data["Generated"], "%d/%m/%Y %H:%M %p").date()

        for item in data["Vulnerabilities"]:
            title = item["Name"]
            findingdetail = html2text.html2text(item.get("Description", ""))
            cwe = int(item["Classification"]["Cwe"]) if "Cwe" in item["Classification"] else None
            sev = item["Severity"]
            if sev not in ['Info', 'Low', 'Medium', 'High', 'Critical']:
                sev = 'Info'
            mitigation = html2text.html2text(item.get("RemedialProcedure", ""))
            references = html2text.html2text(item.get("RemedyReferences", ""))
            url = item["Url"]
            impact = html2text.html2text(item.get("Impact", ""))
            dupe_key = title
            request = item["HttpRequest"]["Content"]
            if request is None or len(request) <= 0:
                request = "Request Not Found"
            response = item["HttpResponse"]["Content"]
            if response is None or len(response) <= 0:
                response = "Response Not Found"

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
