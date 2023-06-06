import hashlib
import re

import html2text
from defusedxml.ElementTree import parse

from dojo.models import Endpoint, Finding


class MicrofocusWebinspectParser(object):
    """Micro Focus Webinspect XML report parser"""

    def get_scan_types(self):
        return ["Microfocus Webinspect Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import XML report"

    def get_findings(self, file, test):
        tree = parse(file)
        # get root of tree.
        root = tree.getroot()
        if 'Sessions' not in root.tag:
            raise ValueError("This doesn't seem to be a valid Webinspect xml file.")

        dupes = dict()
        for session in root:
            url = session.find('URL').text
            endpoint = Endpoint.from_uri(url)
            issues = session.find('Issues')
            for issue in issues.findall('Issue'):
                mitigation = None
                reference = None
                severity = MicrofocusWebinspectParser.convert_severity(issue.find('Severity').text)
                for content in issue.findall('ReportSection'):
                    name = content.find('Name').text
                    if 'Summary' in name:
                        if content.find('SectionText').text:
                            description = content.find('SectionText').text
                    if 'Fix' in name:
                        if content.find('SectionText').text:
                            mitigation = content.find('SectionText').text
                    if 'Reference' in name:
                        if name and content.find('SectionText').text:
                            reference = html2text.html2text(content.find('SectionText').text)
                cwe = 0
                description = ""
                classifications = issue.find('Classifications')
                for content in classifications.findall('Classification'):
                    # detect CWE number
                    # TODO support more than one CWE number
                    if "kind" in content.attrib and "CWE" == content.attrib["kind"]:
                        cwe = MicrofocusWebinspectParser.get_cwe(content.attrib['identifier'])
                        description += "\n\n" + content.text + "\n"

                finding = Finding(
                    title=issue.findtext('Name'),
                    test=test,
                    cwe=cwe,
                    description=description,
                    mitigation=mitigation,
                    severity=severity,
                    references=reference,
                    static_finding=False,
                    dynamic_finding=True,
                    nb_occurences=1,
                )
                if "id" in issue.attrib:
                    finding.unique_id_from_tool = issue.attrib.get("id")
                # manage endpoint
                finding.unsaved_endpoints = [endpoint]

                # make dupe hash key
                dupe_key = hashlib.sha256("|".join([
                    finding.description,
                    finding.title,
                    finding.severity,
                ]).encode('utf-8')).hexdigest()
                # check if dupes are present.
                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    find.unsaved_endpoints.extend(finding.unsaved_endpoints)
                    find.nb_occurences += finding.nb_occurences
                else:
                    dupes[dupe_key] = finding

        return list(dupes.values())

    @staticmethod
    def convert_severity(val):
        if val == "0":
            return "Info"
        elif val == "1":
            return "Low"
        elif val == "2":
            return "Medium"
        elif val == "3":
            return "High"
        else:
            return "Info"

    @staticmethod
    def get_cwe(val):
        # Match only the first CWE!
        cweSearch = re.search("CWE-(\\d+)", val, re.IGNORECASE)
        if cweSearch:
            return int(cweSearch.group(1))
        else:
            return 0
