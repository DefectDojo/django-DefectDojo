import re
import hashlib
import logging

from defusedxml.ElementTree import parse

from dojo.models import Endpoint, Finding


logger = logging.getLogger(__name__)


class WapitiParser(object):
    """The web-application vulnerability scanner

    see: https://wapiti.sourceforge.io/
    """

    def get_scan_types(self):
        return ["Wapiti Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Wapiti Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import XML report"

    def get_findings(self, file, test):
        tree = parse(file)
        # get root of tree.
        root = tree.getroot()
        # check if it is
        if 'report' not in root.tag:
            raise ValueError("This doesn't seem to be a valid Wapiti XML file.")

        severity_mapping = {
            '4': 'Critical',
            '3': 'High',
            '2': 'Medium',
            '1': 'Low',
            '0': 'Info',
        }

        url = root.findtext('report_infos/info[@name="target"]')

        dupes = dict()
        for vulnerability in root.findall('vulnerabilities/vulnerability'):
            category = vulnerability.attrib['name']
            description = vulnerability.findtext('description')
            mitigation = vulnerability.findtext('solution')
            # manage references
            cwe = None
            references = []
            for reference in vulnerability.findall('references/reference'):
                reference_title = reference.findtext('title')
                if reference_title.startswith("CWE"):
                    cwe = self.get_cwe(reference_title)
                references.append(f"* [{reference_title}]({reference.findtext('url')})")
            references = "\n".join(references)

            for entry in vulnerability.findall('entries/entry'):
                title = category + ": " + entry.findtext('info')
                # get numerical severity.
                num_severity = entry.findtext('level')
                if num_severity in severity_mapping:
                    severity = severity_mapping[num_severity]
                else:
                    severity = "Info"

                finding = Finding(
                    title=title,
                    description=description,
                    severity=severity,
                    mitigation=mitigation,
                    references=references,
                    dynamic_finding=True,
                    static_finding=False,
                    nb_occurences=1,
                )
                if cwe:
                    finding.cwe = cwe
                finding.unsaved_endpoints = [Endpoint.from_uri(url)]

                finding.unsaved_req_resp = [{"req": entry.findtext('http_request'), "resp": ""}]

                # make dupe hash key
                dupe_key = hashlib.sha256(str(description + title + severity).encode('utf-8')).hexdigest()
                # check if dupes are present.
                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    find.unsaved_endpoints.extend(finding.unsaved_endpoints)
                    find.unsaved_req_resp.extend(finding.unsaved_req_resp)
                    find.nb_occurences += finding.nb_occurences
                else:
                    dupes[dupe_key] = finding

        return list(dupes.values())

    @staticmethod
    def get_cwe(val):
        # Match only the first CWE!
        cweSearch = re.search("CWE-(\\d+)", val, re.IGNORECASE)
        if cweSearch:
            return int(cweSearch.group(1))
        else:
            return None
