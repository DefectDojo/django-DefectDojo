import re
import html2text
from defusedxml import ElementTree as ET
from dojo.models import Finding


class SpotbugsParser(object):
    """Parser for XML ouput file from Spotbugs (https://github.com/spotbugs/spotbugs)"""

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

        html_parser = html2text.HTML2Text()
        html_parser.ignore_links = False

        # Parse <BugPattern> tags
        for pattern in root.findall('BugPattern'):
            # Parse <BugPattern>...<Details> html content
            html_text = html_parser.handle(
                ET.tostring(
                    pattern.find('Details'),
                    method='text'
                ).decode('utf-8')
            )

            # Parse mitigation from html
            mitigation = ''
            i = 0
            for line in html_text.splitlines():
                i += 1
                # Break loop when references are reached
                if 'Reference' in line:
                    break
                # Add a string before the code indicating that it's just an example, NOT the actual scanned code
                if ('Vulnerable Code:' in line) or ('Insecure configuration:' in line) or ('Code at risk:' in line):
                    mitigation += '\n\n#### Example\n'
                # Add line to mitigation
                mitigation += line + '\n'
            # Add mitigations to dictionary
            mitigation_patterns[pattern.get('type')] = mitigation

            # Parse references from html
            reference = ''
            #   Sometimes there's a breakline in the middle of the reference,
            #   so the splitlines method ends up breaking it in two.
            #   We solve this problem by joining all references and adding breaklines with regex.
            # Start loop where the previous loop ended
            for line in html_text.splitlines()[i:]:
                # Concatenate all references in one big string
                reference += line + ' '
            # Add breakline between each reference
            #   regex: turns ')  [' into ')\n['
            #      ')': reference ends
            #      '[': reference starts
            reference = re.sub(r'(?<=\))(.*?)(?=\[)', '\n', reference)
            # Add references to dictionary
            reference_patterns[pattern.get('type')] = reference

        # Parse <BugInstance> tags
        for bug in root.findall('BugInstance'):
            desc = ''
            for message in bug.itertext():
                desc += message + '\n'

            shortmessage_extract = bug.find('ShortMessage')
            if shortmessage_extract is not None:
                title = shortmessage_extract.text
            else:
                title = bug.get('type')
            severity = SEVERITY[bug.get('priority')]
            description = desc

            finding = Finding(
                title=title,
                cwe=int(bug.get('cweid', default=0)),
                severity=severity,
                description=description,
                test=test,
                static_finding=True,
                dynamic_finding=False,
                nb_occurences=1
            )

            # find the source line and file on the buginstance
            source_extract = bug.find('SourceLine')
            if source_extract is not None:
                finding.file_path = source_extract.get("sourcepath")
                finding.sast_source_object = source_extract.get("classname")
                finding.sast_source_file_path = source_extract.get("sourcepath")
                if 'start' in source_extract.attrib and source_extract.get("start").isdigit():
                    finding.line = int(source_extract.get("start"))
                    finding.sast_source_line = int(source_extract.get("start"))

            if bug.get('type') in mitigation_patterns:
                finding.mitigation = mitigation_patterns[bug.get('type')]
                finding.references = reference_patterns[bug.get('type')]

            if 'instanceHash' in bug.attrib:
                dupe_key = bug.get('instanceHash')
            else:
                dupe_key = "|".join([
                    'no_instance_hash',
                    title,
                    description,
                ])

            if dupe_key in dupes:
                find = dupes[dupe_key]
                find.nb_occurences += 1
            else:
                dupes[dupe_key] = finding

        return list(dupes.values())
