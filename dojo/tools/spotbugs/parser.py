__author__ = 'bakalor'
__maintainer__ = "Igor Bakalo"
__email__ = "bigorigor.ua@gmail.com"
__status__ = "Development"

import re

from defusedxml import ElementTree as ET

from dojo.models import Finding


class SpotbugsParser(object):

    def get_scan_types(self):
        return ["SpotBugs Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "XML report of textui cli."

    def get_findings(self, filename, test):
        bug_patterns = dict()
        dupes = dict()

        SEVERITY = {
            '1': 'High',
            '2': 'Medium',
            '3': 'Low'
        }

        tree = ET.parse(filename)
        root = tree.getroot()

        for pattern in root.findall('BugPattern'):
            plain_pattern = re.sub(r'<[b-z/]*?>|<a|</a>|href=', '', ET.tostring(pattern.find('Details'), method='text').decode('utf-8'))
            bug_patterns[pattern.get('type')] = plain_pattern

        for bug in root.findall('BugInstance'):
            desc = ''
            for message in bug.itertext():
                desc += message + '\n'

            dupe_key = bug.get('instanceHash')

            title = bug.find('ShortMessage').text
            cwe = bug.get('cweid', default=0)
            severity = SEVERITY[bug.get('priority')]
            description = desc
            mitigation = bug_patterns[bug.get('type')]

            # find the source line and file on the buginstance
            source_line = None
            source_file = "N/A"

            source_extract = bug.find('SourceLine')
            if source_extract is not None:
                source_file = source_extract.get("sourcepath")
                source_line = int(source_extract.get("start"))

            if dupe_key in dupes:
                finding = dupes[dupe_key]
            else:
                finding = Finding(
                    title=title,
                    cwe=cwe,
                    severity=severity,
                    description=description,
                    mitigation=mitigation,
                    test=test,
                    static_finding=True,
                    line=source_line,
                    file_path=source_file,
                    sast_source_line=source_line,
                    sast_source_file_path=source_file
                )
                dupes[dupe_key] = finding

        return list(dupes.values())
