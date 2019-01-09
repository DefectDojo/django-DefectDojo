from __future__ import with_statement

from datetime import datetime
from xml.dom import NamespaceErr

from defusedxml import ElementTree

from dojo.models import Endpoint, Finding
import html2text
import urllib.parse

__author__ = "Jay Paz"


class AppSpiderXMLParser(object):
    def __init__(self, filename, test):

        if "VulnerabilitiesSummary.xml" not in str(filename):
            raise NamespaceErr('Please ensure that you are uploading AppSpider\'s VulnerabilitiesSummary.xml file.'
                               'At this time it is the only file that is consumable by DefectDojo.')

        vscan = ElementTree.parse(filename)
        root = vscan.getroot()

        if "VulnSummary" not in str(root.tag):
            raise NamespaceErr('Please ensure that you are uploading AppSpider\'s VulnerabilitiesSummary.xml file.'
                               'At this time it is the only file that is consumable by DefectDojo.')

        dupes = dict()

        for finding in root.iter('Vuln'):

            severity = finding.find("AttackScore").text
            if severity == "0-Safe":
                severity = "Info"
            elif severity == "1-Informational":
                severity = "Low"
            elif severity == "2-Low":
                severity = "Medium"
            elif severity == "3-Medium":
                severity = "High"
            elif severity == "4-High":
                severity = "Critical"
            else:
                severity = "Info"

            title = finding.find("VulnType").text
            description = finding.find("Description").text
            mitigation = finding.find("Recommendation").text
            vuln_url = finding.find("VulnUrl").text

            parts = urllib.parse.urlparse(vuln_url)

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
                               active=False,
                               verified=False,
                               description=html2text.html2text(description),
                               severity=severity,
                               numerical_severity=Finding.get_numerical_severity(severity),
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

                find.unsaved_endpoints.append(Endpoint(protocol=parts.scheme,
                                                       host=parts.netloc,
                                                       path=parts.path,
                                                       query=parts.query,
                                                       fragment=parts.fragment,
                                                       product=test.engagement.product))

        self.items = list(dupes.values())
