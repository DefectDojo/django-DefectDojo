import hashlib
from xml.dom import NamespaceErr

from defusedxml import ElementTree

from dojo.models import Endpoint, Finding

__author__ = 'properam'


class ImmuniwebParser(object):

    def get_scan_types(self):
        return ["Immuniweb Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "XML Scan Result File from Imuniweb Scan."

    def get_findings(self, file, test):

        ImmuniScanTree = ElementTree.parse(file)
        root = ImmuniScanTree.getroot()
        # validate XML file
        if 'Vulnerabilities' not in root.tag:
            raise NamespaceErr("This does not look like a valid expected Immuniweb XML file.")

        dupes = dict()

        for vulnerability in root.iter("Vulnerability"):
            """
                The Tags available in XML File are:
                ID, Name, Date, Status,
                Type, CWE_ID, CVE_ID, CVSSv3,
                Risk, URL, Description, PoC
            """
            mitigation = "N/A"
            impact = "N/A"
            title = vulnerability.find('Name').text
            reference = vulnerability.find('ID').text
            cwe = ''.join(i for i in vulnerability.find('CWE-ID').text if i.isdigit())
            if cwe:
                cwe = cwe
            else:
                cwe = None
            vulnerability_id = vulnerability.find('CVE-ID').text
            steps_to_reproduce = vulnerability.find('PoC').text
            # just to make sure severity is in the recognised sentence casing form
            severity = vulnerability.find('Risk').text.capitalize()
            # Set 'Warning' severity === 'Informational'
            if severity == 'Warning':
                severity = "Informational"

            description = (vulnerability.find('Description').text)
            url = vulnerability.find("URL").text

            dupe_key = hashlib.md5(str(description + title + severity).encode('utf-8')).hexdigest()

            # check if finding is a duplicate
            if dupe_key in dupes:
                finding = dupes[dupe_key]  # fetch finding
                if description is not None:
                    finding.description += description
            else:  # finding is not a duplicate
                # create finding
                finding = Finding(title=title,
                    test=test,
                    description=description,
                    severity=severity,
                    steps_to_reproduce=steps_to_reproduce,
                    cwe=cwe,
                    mitigation=mitigation,
                    impact=impact,
                    references=reference,
                    dynamic_finding=True)
                if vulnerability_id:
                    finding.unsaved_vulnerability_ids = [vulnerability_id]
                finding.unsaved_endpoints = list()
                dupes[dupe_key] = finding

                finding.unsaved_endpoints.append(Endpoint.from_uri(url))

        return list(dupes.values())
