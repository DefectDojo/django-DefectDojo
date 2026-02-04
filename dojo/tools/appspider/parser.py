import html2text
from defusedxml import ElementTree
from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.url.models import URL


class AppSpiderParser:

    """Parser for Rapid7 AppSpider reports"""

    def get_scan_types(self):
        return ["AppSpider Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AppSpider Scan"

    def get_description_for_scan_types(self, scan_type):
        return "AppSpider (Rapid7) - Use the VulnerabilitiesSummary.xml file found in the zipped report download."

    def get_findings(self, filename, test):
        if filename is None:
            return None

        vscan = ElementTree.parse(filename)
        root = vscan.getroot()

        if "VulnSummary" not in str(root.tag):
            msg = (
                "Please ensure that you are uploading AppSpider's VulnerabilitiesSummary.xml file."
                "At this time it is the only file that is consumable by DefectDojo."
            )
            raise ValueError(msg)

        dupes = {}

        for finding in root.iter("Vuln"):
            severity = self.convert_severity(finding.find("AttackScore").text)
            title = finding.find("VulnType").text
            description = finding.find("Description").text
            mitigation = finding.find("Recommendation").text
            vuln_url = finding.find("VulnUrl").text

            cwe = int(finding.find("CweId").text)

            dupe_key = severity + title

            if title is None:
                title = ""
            if description is None:
                description = ""
            if mitigation is None:
                mitigation = ""

            find = Finding(
                title=title,
                test=test,
                description=html2text.html2text(description),
                severity=severity,
                mitigation=html2text.html2text(mitigation),
                impact="N/A",
                references=None,
                cwe=cwe,
            )

            find.unsaved_req_resp = []

            for attack in finding.iter("AttackRequest"):
                req = attack.find("Request").text
                resp = attack.find("Response").text

                find.unsaved_req_resp.append({"req": req, "resp": resp})

            if settings.V3_FEATURE_LOCATIONS:
                find.unsaved_locations.append(URL.from_value(vuln_url))
            else:
                # TODO: Delete this after the move to Locations
                find.unsaved_endpoints.append(Endpoint.from_uri(vuln_url))

            if dupe_key in dupes:
                orig_finding = dupes[dupe_key]
                orig_finding.unsaved_request.extend(find.unsaved_req_resp)
                if settings.V3_FEATURE_LOCATIONS:
                    orig_finding.unsaved_locations.extend(find.unsaved_locations)
                else:
                    # TODO: Delete this after the move to Locations
                    orig_finding.unsaved_endpoints.extend(find.unsaved_endpoints)
            else:
                dupes[dupe_key] = find

        return list(dupes.values())

    @staticmethod
    def convert_severity(val):
        severity = "Info"
        if val == "0-Safe":
            severity = "Info"
        elif val == "1-Informational":
            severity = "Low"
        elif val == "2-Low":
            severity = "Medium"
        elif val == "3-Medium":
            severity = "High"
        elif val == "4-High":
            severity = "Critical"
        return severity
