import json
import html2text

from cvss import parser as cvss_parser
from dateutil import parser
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
        scan_date = parser.parse(data["Generated"])
        text_maker = html2text.HTML2Text()
        text_maker.body_width = 0

        for item in data["Vulnerabilities"]:
            title = item["Name"]
            findingdetail = text_maker.handle(item.get("Description", ""))
            if "Cwe" in item["Classification"]:
                try:
                    cwe = int(item["Classification"]["Cwe"].split(',')[0])
                except:
                    cwe = None
            else:
                cwe = None
            sev = item["Severity"]
            if sev not in ['Info', 'Low', 'Medium', 'High', 'Critical']:
                sev = 'Info'
            mitigation = text_maker.handle(item.get("RemedialProcedure", ""))
            references = text_maker.handle(item.get("RemedyReferences", ""))
            if "LookupId" in item:
                lookupId = item["LookupId"]
                references = f"https://online.acunetix360.com/issues/detail/{lookupId}\n" + references
            url = item["Url"]
            impact = text_maker.handle(item.get("Impact", ""))
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
                cvss_objects = cvss_parser.parse_cvss_from_text(item["Classification"]["Cvss"]["Vector"])
                if len(cvss_objects) > 0:
                    finding.cvssv3 = cvss_objects[0].clean_vector()

            if item["State"] is not None:
                state = [x.strip() for x in item["State"].split(',')]
                if "AcceptedRisk" in state:
                    finding.risk_accepted = True
                    finding.active = False
                elif "FalsePositive" in state:
                    finding.false_p = True
                    finding.active = False

            finding.unsaved_req_resp = [{"req": request, "resp": response}]
            finding.unsaved_endpoints = [Endpoint.from_uri(url)]

            if item.get("FirstSeenDate"):
                parseddate = parser.parse(item["FirstSeenDate"])
                finding.date = parseddate

            if dupe_key in dupes:
                find = dupes[dupe_key]
                find.unsaved_req_resp.extend(finding.unsaved_req_resp)
                find.unsaved_endpoints.extend(finding.unsaved_endpoints)
            else:
                dupes[dupe_key] = finding

        return list(dupes.values())
