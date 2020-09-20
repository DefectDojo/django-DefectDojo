import json
from dojo.models import Finding


class CheckovParser(object):

    def __init__(self, json_output, test):
        self.items = []

        if json_output is None:
            return

        tree = self.parse_json(json_output)

        check_type = ''
        if 'check_type' in tree:
            check_type = tree['check_type']

        if tree:
            self.items = [data for data in self.get_items(tree, test, check_type)]

    def parse_json(self, json_output):
        try:
            data = json_output.read()
            try:
                tree = json.loads(str(data, 'utf-8'))
            except:
                tree = json.loads(data)
        except:
            raise Exception("Invalid format")

        return tree

    def get_items(self, tree, test, check_type):
        items = []

        for node in tree['results']['failed_checks']:
            item = get_item(node, test, check_type)
            if item:
                items.append(item)

        return list(items)


def get_item(vuln, test, check_type):

    unique_id_from_tool = None

    title = ''
    if 'check_name' in vuln:
        title = vuln['check_name']
    else:
        title = 'check_name not found'

    description = 'Check Type: {}\n'.format(check_type)
    if 'check_id' in vuln:
        description += 'Check Id: {}\n'.format(vuln['check_id'])
    if 'check_name' in vuln:
        description += '{}\n'.format(vuln['check_name'])

    file_path = None
    if 'file_path' in vuln:
        file_path = vuln['file_path']

    sast_source_line = None
    line_sink = None
    if 'file_line_range' in vuln:
        lines = vuln['file_line_range']
        sast_source_line = lines[0]
        line_sink = lines[1]

    sast_object = None
    if 'resource' in vuln:
        sast_object = vuln['resource']

    # Checkov doesn't define severities. Sine the findings are
    # vulnerabilities, we set them to Medium
    severity = 'Medium'
    numerical_severity = Finding.get_numerical_severity(severity)

    sourcefile = None
    scanner_confidence = None
    mitigation = ''
    cwe = None
    cve = None

    references = ''
    if 'guideline' in vuln:
        references = vuln['guideline']

    finding = Finding(title=title,
                      test=test,
                      active=False,
                      verified=False,
                      description=description,
                      severity=severity,
                      numerical_severity=numerical_severity,
                      scanner_confidence=scanner_confidence,
                      mitigation=mitigation,
                      unique_id_from_tool=unique_id_from_tool,
                      references=references,
                      file_path=file_path,
                      sourcefile=sourcefile,
                      line=line_sink,
                      sast_source_object=sast_object,
                      sast_sink_object=sast_object,
                      sast_source_file_path=file_path,
                      sast_source_line=sast_source_line,
                      cwe=cwe,
                      cve=cve,
                      static_finding=True,
                      dynamic_finding=False)

    return finding
