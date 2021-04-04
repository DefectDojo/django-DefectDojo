__author__ = 'bakalor'
__maintainer__ = "Igor Bakalo"
__email__ = "bigorigor.ua@gmail.com"
__status__ = "Development"

import re
from bs4 import BeautifulSoup
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
        mitigation_patterns = dict()
        reference_patterns = dict()
        dupes = dict()

        SEVERITY = {
            '1': 'High',
            '2': 'Medium',
            '3': 'Low'
        }

        tree = ET.parse(filename)
        root = tree.getroot()

        # Parse <BugPattern> tags
        for pattern in root.findall('BugPattern'):
            # Parse <BugPattern> content as html
            html_text = BeautifulSoup(ET.tostring(pattern.find('Details'), method='text').decode('utf-8'), features="html.parser")

            # Surround text inside <pre> tags with ```
            for pre in html_text.find_all('pre'):
                temp = pre.text
                pre.string = '```\n'+temp+'\n```'
            # Surround text inside <code> tags with `
            for code in html_text.find_all('code'):
                temp = code.text
                code.string = '`'+temp+'`'
            # Surround text inside <b> tags with **
            for bold in html_text.find_all('b'):
                temp = bold.text
                bold.string = '**'+temp+'**'

            # Get <p> tags
            paragraphs = html_text.find_all('p')

            # All <p> tags (except the last one) are the bug description with instructions on how to fix it
            mitigation = ''
            for p in paragraphs[:-1]:
                if ('Vulnerable Code:' in p.text) or ('Insecure configuration:' in p.text) or ('Code at risk:' in p.text):
                    # Add a string indicating the code here its just an example, NOT the actual scanned code
                    mitigation += '\n\n\n#### Example\n'
                # Append text removing leading whitespaces if is not a code
                mitigation += re.sub("  +", "", p.text) if '```' not in p.text else p.text
            mitigation_patterns[pattern.get('type')] = mitigation

            # The last <p> is always references
            reference = ''
            links = paragraphs[-1].find_all('a', href=True)
            for link in links:
                reference += link['href']+' - '+link.text+'\n'
            reference_patterns[pattern.get('type')] = reference

        # Parse <BugInstance> tags
        for bug in root.findall('BugInstance'):
            desc = ''
            for message in bug.itertext():
                # The message comes with multiple breaklines,
                # so were removing all of them and adding only one at the end
                desc += message.replace('\n','')+'\n'

            dupe_key = bug.get('instanceHash')

            title = bug.find('ShortMessage').text
            cwe = bug.get('cweid', default=0)
            severity = SEVERITY[bug.get('priority')]
            description = desc
            mitigation = mitigation_patterns[bug.get('type')]
            references = reference_patterns[bug.get('type')]

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
                    references=references,
                    test=test,
                    active=False,
                    verified=False,
                    numerical_severity=Finding.get_numerical_severity(severity),
                    static_finding=True,
                    line=source_line,
                    file_path=source_file,
                    sast_source_line=source_line,
                    sast_source_file_path=source_file
                )
                dupes[dupe_key] = finding

        return list(dupes.values())
