import json

from dojo.models import Finding


class CheckovParser(object):

    def get_scan_types(self):
        return ["Checkov Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Checkov Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON reports of Infrastructure as Code vulnerabilities."

    def get_findings(self, json_output, test):
        findings = list()
        if json_output:
            deserialized = self.parse_json(json_output)
            for tree in deserialized:
                check_type = tree['check_type']
                findings += self.get_items(tree, test, check_type)

        return findings

    def parse_json(self, json_output):
        """Parse JSON report.
        Checkov may return only one `check_type` (where the report is just a JSON)
        or more (where the report is an array of JSONs).
        To address all scenarios we force this method to return a list of JSON objects.

        :param json_output: JSON report
        :type json_output: file
        :return: JSON array of objects
        :rtype: list
        """
        try:
            data = json_output.read()
            try:
                deserialized = json.loads(str(data, 'utf-8'))
            except:
                deserialized = json.loads(data)
        except:
            raise Exception("Invalid format")

        if type(deserialized) is not list:
            return [deserialized]
        else:
            return deserialized

    def get_items(self, tree, test, check_type):
        items = []

        for node in tree['results']['failed_checks']:
            item = get_item(node, test, check_type)
            if item:
                items.append(item)

        return list(items)


def get_item(vuln, test, check_type):
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

    source_line = None
    if 'file_line_range' in vuln:
        lines = vuln['file_line_range']
        source_line = lines[0]

    resource = None
    if 'resource' in vuln:
        resource = vuln['resource']

    # Checkov doesn't define severities. Sine the findings are
    # vulnerabilities, we set them to Medium
    severity = 'Medium'

    mitigation = ''

    references = ''
    if 'guideline' in vuln:
        references = vuln['guideline']

    finding = Finding(title=title,
                      test=test,
                      description=description,
                      severity=severity,
                      mitigation=mitigation,
                      references=references,
                      file_path=file_path,
                      line=source_line,
                      component_name=resource,
                      static_finding=True,
                      dynamic_finding=False)

    return finding
