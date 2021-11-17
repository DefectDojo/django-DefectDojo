import json

from dojo.models import Finding
from dojo.tools.parser_test import ParserTest


class GitlabSastParser(object):

    def get_scan_types(self):
        return ["GitLab SAST Report"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import GitLab SAST Report vulnerabilities in JSON format."

    def get_findings(self, json_output, test):

        if json_output is None:
            return

        tree = self.parse_json(json_output)
        if tree:
            return self.get_items(tree)

    def get_tests(self, scan_type, handle):
        tree = self.parse_json(handle)
        tests = list()

        scan = tree.get('scan')
        if scan:
            scanner_name = scan['scanner']['name']
            scanner_type = scan['scanner']['name']
            scanner_version = scan['scanner']['version']
        else:
            scanner_name = scanner_type = scanner_version = None

        test = ParserTest(
            name=scanner_name,
            type=scanner_type,
            version=scanner_version
        )
        test.findings = self.get_items(tree)
        tests.append(test)
        return tests

    def parse_json(self, json_output):
        data = json_output.read()
        try:
            tree = json.loads(str(data, 'utf-8'))
        except:
            tree = json.loads(data)

        return tree

    def get_items(self, tree):
        items = {}

        for node in tree['vulnerabilities']:
            item = get_item(node)
            if item:
                items[item.unique_id_from_tool] = item

        return list(items.values())


def get_item(vuln):
    if vuln['category'] != 'sast':
        # For SAST reports, value must always be "sast"
        return None

    unique_id_from_tool = None
    if 'id' in vuln:
        unique_id_from_tool = vuln['id']
    else:
        # If the new unique id is not provided, fall back to deprecated "cve" fingerprint (old version)
        unique_id_from_tool = vuln['cve']

    title = ''
    if 'name' in vuln:
        title = vuln['name']
    elif 'message' in vuln:
        title = vuln['message']
    elif 'description' in vuln:
        title = vuln['description']
    else:
        # All other fields are optional, if none of them has a value, fall back on the unique id
        title = unique_id_from_tool

    description = 'Scanner: {}\n'.format(vuln['scanner']['name'])
    if 'message' in vuln:
        description += '{}\n'.format(vuln['message'])
    if 'description' in vuln:
        description += '{}\n'.format(vuln['description'])

    location = vuln['location']
    file_path = location['file'] if 'file' in location else None

    line = location['start_line'] if 'start_line' in location else None
    if 'end_line' in location:
        line = location['end_line']

    sast_source_line = location['start_line'] if 'start_line' in location else None

    sast_object = None
    if 'class' in location and 'method' in location:
        sast_object = '{}#{}'.format(location['class'], location['method'])
    elif 'class' in location:
        sast_object = location['class']
    elif 'method' in location:
        sast_object = location['method']

    severity = vuln.get('severity')
    if severity is None or severity == 'Undefined' or severity == 'Unknown':
        # Severity can be "Undefined" or "Unknown" in SAST report
        # In that case we set it as Info and specify the initial severity in the title
        title = '[{} severity] {}'.format(severity, title)
        severity = 'Info'
    scanner_confidence = get_confidence_numeric(vuln.get('confidence', 'Unkown'))

    mitigation = ''
    if 'solution' in vuln:
        mitigation = vuln['solution']

    cwe = None
    cve = None
    references = ''
    if 'identifiers' in vuln:
        for identifier in vuln['identifiers']:
            if identifier['type'].lower() == 'cwe':
                if isinstance(identifier['value'], int):
                    cwe = identifier['value']
                elif identifier['value'].isdigit():
                    cwe = int(identifier['value'])
            elif identifier['type'].lower() == 'cve':
                cve = identifier['value']
            else:
                references += 'Identifier type: {}\n'.format(identifier['type'])
                references += 'Name: {}\n'.format(identifier['name'])
                references += 'Value: {}\n'.format(identifier['value'])
                if 'url' in identifier:
                    references += 'URL: {}\n'.format(identifier['url'])
                references += '\n'

    finding = Finding(title=title,
                      description=description,
                      severity=severity,
                      scanner_confidence=scanner_confidence,
                      mitigation=mitigation,
                      unique_id_from_tool=unique_id_from_tool,
                      references=references,
                      file_path=file_path,
                      line=line,
                      sast_source_object=sast_object,
                      sast_sink_object=sast_object,
                      sast_source_file_path=file_path,
                      sast_source_line=sast_source_line,
                      cwe=cwe,
                      cve=cve,
                      static_finding=True,
                      dynamic_finding=False)

    return finding


def get_confidence_numeric(argument):
    switcher = {
        'Confirmed': 1,    # Certain
        'High': 3,         # Firm
        'Medium': 4,       # Firm
        'Low': 6,          # Tentative
        'Experimental': 7  # Tentative
    }
    return switcher.get(argument, None)
