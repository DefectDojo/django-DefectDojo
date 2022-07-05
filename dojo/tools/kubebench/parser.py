import json

from dojo.models import Finding


class KubeBenchParser(object):

    def get_scan_types(self):
        return ["kube-bench Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON reports of Kubernetes CIS benchmark scans."

    def get_findings(self, json_output, test):
        tree = json.load(json_output)
        if 'Controls' in tree:
            return self.get_chapters(tree['Controls'], test)
        else:
            return self.get_chapters(tree, test)

    def get_chapters(self, tree, test):
        items = []

        for node in tree:
            items_from_tests = get_tests(node, test)
            items += items_from_tests

        return list(items)


def get_tests(tree, test):
    items_from_tests = []

    description = ''
    if 'id' in tree:
        description += tree['id'] + " "
    if 'text' in tree:
        description += tree['text']
    description += '\n'

    for node in tree['tests']:
        items_from_results = get_results(node, test, description)
        items_from_tests += items_from_results

    return list(items_from_tests)


def get_results(tree, test, description):
    items_from_results = []

    if 'section' in tree:
        description += tree['section'] + ' '
    if 'desc' in tree:
        description += tree['desc']
    description += '\n'

    for node in tree['results']:
        item = get_item(node, test, description)
        if item:
            items_from_results.append(item)

    return list(items_from_results)


def get_item(vuln, test, description):

    status = vuln.get('status', None)
    reason = vuln.get('reason', None)

    if status is None:
        return None

    # kube-bench doesn't define severities. So we use the status to define the severity
    if status.upper() == 'FAIL':
        severity = 'Medium'
    elif status.upper() == 'WARN' and reason != 'Test marked as a manual test':
        severity = 'Info'
    else:
        return None

    test_number = vuln.get('test_number', 'Test number not found')
    test_description = vuln.get('test_desc', 'Description not found')

    title = test_number + ' - ' + test_description

    if 'test_number' in vuln:
        description += vuln['test_number'] + ' '
    if 'test_desc' in vuln:
        description += vuln['test_desc']
    if 'audit' in vuln:
        description += '\n'
        description += 'Audit: {}\n'.format(vuln['audit'])
    if 'reason' in vuln and vuln['reason'] != '':
        description += '\n'
        description += 'Reason: {}\n'.format(vuln['reason'])
    if 'expected_result' in vuln and vuln['expected_result'] != '':
        description += '\n'
        description += 'Expected result: {}\n'.format(vuln['expected_result'])
    if 'actual_value' in vuln and vuln['actual_value'] != '':
        description += '\n'
        description += 'Actual value: {}\n'.format(vuln['actual_value'])

    mitigation = vuln.get('remediation', None)
    vuln_id_from_tool = test_number

    finding = Finding(title=title,
                      test=test,
                      description=description,
                      severity=severity,
                      mitigation=mitigation,
                      vuln_id_from_tool=vuln_id_from_tool,
                      static_finding=True,
                      dynamic_finding=False)

    return finding
