import logging
from datetime import datetime

import html2text
from dateutil import parser
from defusedxml import ElementTree

from dojo.models import Endpoint, Finding

logger = logging.getLogger(__name__)


def htmltext(blob):
    h = html2text.HTML2Text()
    h.ignore_links = False
    return h.handle(blob)


def issue_r(raw_row, vuln, scan_date):
    ret_rows = []
    issue_row = {}

    # IP ADDRESS
    issue_row["ip_address"] = raw_row.get("value")

    # FQDN
    issue_row["fqdn"] = raw_row.get("name")
    if issue_row["fqdn"] == "No registered hostname":
        issue_row["fqdn"] = None
    # port
    port = raw_row.get("port")

    # Create Endpoint
    ep = Endpoint(host=issue_row["fqdn"]) if issue_row["fqdn"] else Endpoint(host=issue_row["ip_address"])

    # OS NAME
    issue_row["os"] = raw_row.findtext("OS")

    # Scan details - VULNS//VULN indicates we only care about confirmed
    # vulnerabilities
    for vuln_cat in raw_row.findall("VULNS/CAT"):
        category = str(vuln_cat.get("value"))
        for vuln_details in vuln_cat.findall("VULN"):
            temp = issue_row

            gid = vuln_details.get("number")

            temp["port_status"] = port

            result = str(vuln_details.findtext("RESULT"))

            # Vuln name
            temp["vuln_name"] = vuln_details.findtext("TITLE")

            # Vuln Description
            description = str(vuln_details.findtext("DIAGNOSIS"))
            # Solution Strips Heading Workaround(s)
            temp["solution"] = htmltext(
                str(vuln_details.findtext("SOLUTION")),
            )

            # Vuln_description
            temp["vuln_description"] = "\n".join(
                [
                    htmltext(description),
                    htmltext("**Category:** " + category),
                    htmltext("**QID:** " + str(gid)),
                    htmltext("**Port:** " + str(port)),
                    htmltext("**Result Evidence:** " + result),
                ],
            )
            # Impact description
            temp["IMPACT"] = htmltext(
                str(vuln_details.findtext("CONSEQUENCE")),
            )

            # CVE and LINKS
            cl = []
            temp_cve_details = vuln_details.iterfind("CVE_ID_LIST/CVE_ID")
            if temp_cve_details:
                cl = {
                    cve_detail.findtext("ID"): cve_detail.findtext("URL")
                    for cve_detail in temp_cve_details
                }
                temp["cve"] = "\n".join(list(cl.keys()))
                temp["links"] = "\n".join(list(cl.values()))

            # The CVE in Qualys report might not have a CVSS score, so findings are informational by default
            # unless we can find map to a Severity OR a CVSS score from the
            # findings detail.
            sev = qualys_convert_severity(vuln_details.get("severity"))

            refs = "\n".join(list(cl.values()))
            finding = Finding(
                title=temp["vuln_name"],
                mitigation=temp["solution"],
                description=temp["vuln_description"],
                severity=sev,
                references=refs,
                impact=temp["IMPACT"],
                vuln_id_from_tool=gid,
                date=scan_date,
            )
            finding.unsaved_endpoints = []
            finding.unsaved_endpoints.append(ep)
            ret_rows.append(finding)
    return ret_rows


def qualys_convert_severity(raw_val):
    val = str(raw_val).strip()
    if val == "1":
        return "Info"
    if val == "2":
        return "Low"
    if val == "3":
        return "Medium"
    if val == "4":
        return "High"
    if val == "5":
        return "Critical"
    return "Info"


class QualysInfrascanWebguiParser:

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Qualys Infrastructure Webgui Parser.

        Fields:
        - title: Set to title from Qualys Infrastructure Webgui Scanner.
        - mitigation: Set to solution from Qualys Infrastructure Webgui Scanner.
        - description: Custom description made from: description, category, QID, port, and result evidence.
        - severity: Set to severity from Qualys Infrastructure Webgui Scanner translated into DefectDojo formant.
        - impact: Set to consequence from Qualys Infrastructure Webgui Scanner.
        - vuln_id_from_tool: Set to gid from Qualys Infrastructure Webgui Scanner.
        - date: Set to datetime from Qualys Infrastructure Webgui Scanner.
        """
        return [
            "title",
            "mitigation",
            "description",
            "severity",
            "impact",
            "vuln_id_from_tool",
            "date",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Qualys Infrastructure Webgui Parser.

        Fields:
        - title: Set to title from Qualys Infrastructure Webgui Scanner.
        - severity: Set to severity from Qualys Infrastructure Webgui Scanner translated into DefectDojo formant.

        NOTE: endpoints is not provided by parser
        """
        return [
            "title",
            "severity",
        ]

    def get_scan_types(self):
        return ["Qualys Infrastructure Scan (WebGUI XML)"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Qualys WebGUI output files can be imported in XML format."

    def get_findings(self, file, test):
        data = ElementTree.parse(file).getroot()

        # fetch scan date e.g.: <KEY value="DATE">2020-01-30T09:45:41Z</KEY>
        scan_date = datetime.now()
        for i in data.findall("HEADER/KEY"):
            if i.get("value") == "DATE":
                scan_date = parser.isoparse(i.text)

        master_list = []
        for issue in data.findall("IP"):
            master_list += issue_r(issue, data, scan_date)
        return master_list
