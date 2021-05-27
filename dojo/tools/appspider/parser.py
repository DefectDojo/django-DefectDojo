from xml.dom import NamespaceErr

import html2text
from defusedxml import ElementTree

from dojo.models import Endpoint, Finding


class AppSpiderParser(object):
    """Parser for Rapid7 AppSpider reports"""

    def get_scan_types(self):
        return ["AppSpider Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AppSpider Scan"

    def get_description_for_scan_types(self, scan_type):
        return "AppSpider (Rapid7) - Use the VulnerabilitiesSummary.xml file found in the zipped report download."

    def get_findings(self, filename, test):

        if filename is None:
            return

        vscan = ElementTree.parse(filename)
        root = vscan.getroot()

        if "VulnSummary" not in str(root.tag):
            raise NamespaceErr('Please ensure that you are uploading AppSpider\'s VulnerabilitiesSummary.xml file.'
                               'At this time it is the only file that is consumable by DefectDojo.')

        dupes = dict()

        for finding in root.iter('Vuln'):
            severity = self.convert_severity(finding.find("AttackScore").text)
            title = finding.find("VulnType").text
            description = finding.find("Description").text
            mitigation = finding.find("Recommendation").text
            vuln_url = finding.find("VulnUrl").text

            cwe = int(finding.find("CweId").text)

            dupe_key = severity + title
            unsaved_endpoints = list()
            unsaved_req_resp = list()

            if title is None:
                title = ''
            if description is None:
                description = ''
            if mitigation is None:
                mitigation = ''

            if dupe_key in dupes:
                find = dupes[dupe_key]

                unsaved_endpoints.append(find.unsaved_endpoints)
                unsaved_req_resp.append(find.unsaved_req_resp)

            else:
                find = Finding(title=title,
                               test=test,
                               description=html2text.html2text(description),
                               severity=severity,
                               mitigation=html2text.html2text(mitigation),
                               impact="N/A",
                               references=None,
                               cwe=cwe)
                find.unsaved_endpoints = unsaved_endpoints
                find.unsaved_req_resp = unsaved_req_resp
                dupes[dupe_key] = find

                for attack in finding.iter("AttackRequest"):
                    req = attack.find("Request").text
                    resp = attack.find("Response").text

                    find.unsaved_req_resp.append({"req": req, "resp": resp})

                endpoint = Endpoint.from_uri(vuln_url)
                find.unsaved_endpoints.append(endpoint)

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
