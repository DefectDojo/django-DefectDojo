import hashlib
import logging

import dateutil
import html2text
import hyperlink
from defusedxml.ElementTree import parse
from dojo.models import Endpoint, Finding

logger = logging.getLogger(__name__)


class AcunetixParser(object):
    """Parser for Acunetix XML files."""

    def get_scan_types(self):
        return ["Acunetix Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Acunetix Scanner"

    def get_description_for_scan_types(self, scan_type):
        return "XML format"

    def get_findings(self, xml_output, test):
        root = parse(xml_output).getroot()

        dupes = dict()
        for scan in root.findall("Scan"):
            start_url = scan.findtext("StartURL")
            if ":" not in start_url:
                start_url = "//" + start_url
            # get report date
            if scan.findtext("StartTime") and "" != scan.findtext("StartTime"):
                report_date = dateutil.parser.parse(scan.findtext("StartTime")).date()

            for item in scan.findall("ReportItems/ReportItem"):

                finding = Finding(
                    test=test,
                    title=item.findtext("Name"),
                    severity=self.get_severity(item.findtext("Severity")),
                    description=html2text.html2text(item.findtext("Description")).strip(),
                    false_p=self.get_false_positive(item.findtext("IsFalsePositive")),
                    static_finding=True,
                    dynamic_finding=False,
                    nb_occurences=1,
                )

                if item.findtext("Impact") and "" != item.findtext("Impact"):
                    finding.impact = item.findtext("Impact")

                if item.findtext("Recommendation") and "" != item.findtext("Recommendation"):
                    finding.mitigation = item.findtext("Recommendation")

                if report_date:
                    finding.date = report_date

                if item.findtext("CWEList/CWE"):
                    finding.cwe = self.get_cwe_number(item.findtext("CWEList/CWE"))

                references = []
                for reference in item.findall("References/Reference"):
                    url = reference.findtext("URL")
                    db = reference.findtext("Database") or url
                    references.append(" * [{}]({})".format(db, url))
                if len(references) > 0:
                    finding.references = "\n".join(references)

                if item.findtext("CVSS3/Descriptor"):
                    finding.cvssv3 = item.findtext("CVSS3/Descriptor")

                # more description are in "Details"
                if item.findtext("Details") and len(item.findtext("Details").strip()) > 0:
                    finding.description += "\n\n**Details:**\n{}".format(html2text.html2text(item.findtext("Details")))
                if item.findtext("TechnicalDetails") and len(item.findtext("TechnicalDetails").strip()) > 0:
                    finding.description += "\n\n**TechnicalDetails:**\n\n{}".format(item.findtext("TechnicalDetails"))

                # add requests
                finding.unsaved_req_resp = list()
                if len(item.findall("TechnicalDetails/Request")):
                    finding.dynamic_finding = True  # if there is some requests it's dynamic
                    finding.static_finding = False  # if there is some requests it's dynamic
                    for request in item.findall("TechnicalDetails/Request"):
                        finding.unsaved_req_resp.append({"req": (request.text or ""), "resp": ""})

                # manage the endpoint
                url = hyperlink.parse(start_url)
                endpoint = Endpoint(
                        host=url.host,
                        port=url.port,
                        path=item.findtext("Affects"),
                )
                if url.scheme is not None and "" != url.scheme:
                    endpoint.protocol = url.scheme
                finding.unsaved_endpoints = [endpoint]

                dupe_key = hashlib.sha256("|".join([
                    finding.title,
                    str(finding.impact),
                    str(finding.mitigation),
                ]).encode("utf-8")).hexdigest()

                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    # add details for the duplicate finding
                    if item.findtext("Details") and len(item.findtext("Details").strip()) > 0:
                        find.description += "\n-----\n\n**Details:**\n{}".format(html2text.html2text(item.findtext("Details")))
                    find.unsaved_endpoints.extend(finding.unsaved_endpoints)
                    find.unsaved_req_resp.extend(finding.unsaved_req_resp)
                    find.nb_occurences += finding.nb_occurences
                    logger.debug("Duplicate finding : {defectdojo_title}".format(defectdojo_title=finding.title))
                else:
                    dupes[dupe_key] = finding

        return list(dupes.values())

    def get_cwe_number(self, cwe):
        """
            Returns cwe number.
        :param cwe:
        :return: cwe number
        """
        if cwe is None:
            return None
        else:
            return int(cwe.split("-")[1])

    def get_severity(self, severity):
        """
            Returns Severity as per DefectDojo standards.
        :param severity:
        :return:
        """
        if severity == "high":
            return "High"
        elif severity == "medium":
            return "Medium"
        elif severity == "low":
            return "Low"
        elif severity == "informational":
            return "Info"
        else:
            return "Critical"

    def get_false_positive(self, false_p):
        """
            Returns True, False for false positive as per DefectDojo standards.
        :param false_p:
        :return:
        """
        if false_p:
            return True
        else:
            return False
