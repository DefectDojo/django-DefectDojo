import json

from dojo.models import Finding
from datetime import datetime


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
    test_start = tree.get('start')
    test_end = tree.get('end')
    description += '\n'

    for node in tree['tests']:
        items_from_results = get_results(node, test, test_start, test_end, description)
        items_from_tests += items_from_results

    return list(items_from_tests)


def get_results(tree, test, test_start, test_end, description):
    items_from_results = []

    if 'section' in tree:
        description += tree['section'] + ' '
    if 'desc' in tree:
        description += tree['desc']
    description += '\n'

    for node in tree['results']:
        item = get_item(node, test, test_start, test_end, description)
        if item:
            items_from_results.append(item)

    return list(items_from_results)


def get_item(vuln, test, test_start, test_end, description):

    status = vuln.get('result')
    reason = vuln.get('desc')

    if status is None:
        return None

    # docker-bench-security doesn't define severities. So we use the status to define the severity
    if status.upper() == 'FAIL':
        severity = 'Critical'
    elif status.upper() == 'WARN' and '(Manual)' not in reason:
        severity = 'High'
    elif status.upper() == 'INFO' and '(Manual)' not in reason:
        severity = 'Low'
    elif status.upper() == 'NOTE' and '(Manual)' not in reason:
        severity = 'Info'
    else:
        return None  # return here, e.g if status is PASS and don't add new finding

    unique_id_from_tool = vuln.get('id')

    test_description = vuln.get('desc', 'No description')
    if unique_id_from_tool:
        title = f'{unique_id_from_tool} - {test_description}'
    else:
        title = f'No test number - {test_description}'

    if unique_id_from_tool:
        description += unique_id_from_tool
    if reason:
        description += '\n'
        description += 'desc: {}\n'.format(reason)
    if vuln.get('details'):
        description += '\n'
        description += vuln['details']
    if vuln.get('audit'):
        description += '\n'
        description += 'Audit: {}\n'.format(vuln['audit'])
    if vuln.get('expected_result'):
        description += '\n'
        description += 'Expected result: {}\n'.format(vuln['expected_result'])
    if vuln.get('actual_value'):
        description += '\n'
        description += 'Actual value: {}\n'.format(vuln['actual_value'])

    mitigation = vuln.get('remediation')
    if vuln.get('remediation-impact'):
        mitigation += '\n'
        mitigation += 'mitigation impact: {}\n'.format(vuln['remediation-impact'])

    finding = Finding(title=title,
                      date=datetime.fromtimestamp(int(test_end)),
                      test=test,
                      description=description,
                      severity=severity,
                      mitigation=mitigation,
                      unique_id_from_tool=unique_id_from_tool,
                      static_finding=True,
                      dynamic_finding=False)

    return finding
