import json
import hashlib
from dojo.models import Finding


class CodeCheckerParser(object):

    def get_scan_types(self):
        return ["Codechecker Report native"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import Codechecker Report in native JSON format."

    def get_requires_file(self, scan_type):
        return True

    def get_findings(self, json_output, test):

        if json_output is None:
            return

        tree = self.parse_json(json_output)
        if tree:
            return self.get_items(tree)

    def parse_json(self, json_output):
        data = json_output.read()
        try:
            tree = json.loads(str(data, 'utf-8'))
        except:
            tree = json.loads(data)

        return tree

    def get_items(self, tree):
        items = {}
        # all findings are in "reports" list
        for node in tree['reports']:
            item = get_item(node)
            if item:
                items[item.unique_id_from_tool] = item

        return list(items.values())


def get_item(vuln):

    description = 'Analyzer name: {}\n'.format(vuln['analyzer_name'])
    description += 'Category name: {}\n'.format(vuln['category'])
    description += 'Checker name: {}\n'.format(vuln['checker_name'])

    if 'type' in vuln:
        vuln_type = vuln.get('type', 'None')
        if vuln_type != 'None':
            description += 'Type: {}\n'.format(vuln_type)

    if 'message' in vuln:
        description += '{}\n'.format(vuln['message'])

    location = vuln['file']
    file_path = location['path'] if 'path' in location else None

    if file_path:
        description += 'File path: {}\n'.format(file_path)

    line = vuln['line'] if 'line' in vuln else None
    column = vuln['column'] if 'column' in vuln else None

    if line is not None and column is not None:
        description += 'Location in file: line {}, column {}\n'.format(line, column)

    sast_source_line = line

    sast_object = None

    severity = get_mapped_severity(vuln.get('severity', 'UNSPECIFIED'))

    mitigation = ''

    references = ''

    review_status = vuln.get('review_status', 'unreviewed')
    verified = review_status == 'confirmed'  # bug confirmed by reviewer
    risk_accepted = review_status == 'intentional'  # not confirmed, not a bug, there are some reasons to make this code in this manner
    false_positive = review_status in ['false_positive', 'suppressed']  # this finding is false positive

    hash = hashlib.sha256()
    unique_id = vuln['report_hash'] + '.' + vuln['analyzer_result_file_path']+description
    hash.update(unique_id.encode())
    unique_id_from_tool = hash.hexdigest()

    title = ''
    if 'checker_name' in vuln:
        title = vuln['checker_name']
    elif 'message' in vuln:
        title = vuln['message']
    else:
        title = unique_id_from_tool

    finding = Finding(title=title,
                      description=description,
                      severity=severity,
                      scanner_confidence=None,
                      mitigation=mitigation,
                      unique_id_from_tool=unique_id_from_tool,
                      references=references,
                      file_path=file_path,
                      line=line,
                      verified=verified,
                      risk_accepted=risk_accepted,
                      false_p=false_positive,
                      sast_source_object=sast_object,
                      sast_sink_object=sast_object,
                      sast_source_file_path=file_path,
                      sast_source_line=sast_source_line,
                      static_finding=True,
                      dynamic_finding=False)

    return finding


def get_mapped_severity(severity):
    switcher = {
        'CRITICAL': 'Critical',
        'HIGH': 'High',
        'MEDIUM': 'Medium',
        'LOW': 'Low',
        'STYLE': 'Informational',
        'UNSPECIFIED': 'Informational',
    }
    return switcher.get(severity.upper(), None)
