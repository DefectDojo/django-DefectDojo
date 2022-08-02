import json

from dojo.models import Finding


class DockerBenchParser(object):

    def get_scan_types(self):
        return ["docker-bench-security Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON reports of Docker CIS benchmark scans."

    def get_findings(self, json_output, test):
        tree = json.load(json_output)

        return get_tests(tree, test)


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

    status = vuln.get('result', None)
    reason = vuln.get('desc', None)

    if status is None:
        return None

    # kube-bench doesn't define severities. So we use the status to define the severity
    if status.upper() == 'FAIL':
        severity = 'Critical'
    elif status.upper() == 'WARN' and '(Manual)' not in reason:
        severity = 'High'
    elif status.upper() == 'INFO' and '(Manual)' not in reason:
        severity = 'Low'
    elif status.upper() == 'NOTE' and '(Manual)' not in reason:
        severity = 'Info'
    else:
        return None

    test_number = vuln.get('id', 'Test number not found')
    test_description = vuln.get('desc', 'Description not found')

    title = test_number + ' - ' + test_description

    if 'id' in vuln:
        description += vuln['id'] + ' '
    if 'desc' in vuln and vuln['desc'] != '':
        description += '\n'
        description += 'desc: {}\n'.format(vuln['desc'])
    if 'details' in vuln:
        description += vuln['details']
    if 'audit' in vuln:
        description += '\n'
        description += 'Audit: {}\n'.format(vuln['audit'])
    if 'expected_result' in vuln and vuln['expected_result'] != '':
        description += '\n'
        description += 'Expected result: {}\n'.format(vuln['expected_result'])
    if 'actual_value' in vuln and vuln['actual_value'] != '':
        description += '\n'
        description += 'Actual value: {}\n'.format(vuln['actual_value'])

    mitigation = vuln.get('remediation', '')
    if 'remediation-impact' in vuln and vuln['remediation-impact'] != '':
        mitigation += '\n'
        mitigation += 'mitigation mpact: {}\n'.format(vuln['remediation-impact'])

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
