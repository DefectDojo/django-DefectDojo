import json
import logging

from dojo.models import Finding

logger = logging.getLogger(__name__)

NEUVECTOR_SCAN_NAME = 'NeuVector (REST)'
NEUVECTOR_IMAGE_SCAN_ENGAGEMENT_NAME = 'NV image scan'
NEUVECTOR_CONTAINER_SCAN_ENGAGEMENT_NAME = 'NV container scan'


class NeuVectorJsonParser(object):
    def parse(self, json_output, test):
        tree = self.parse_json(json_output)
        items = []
        if tree:
            items = [data for data in self.get_items(tree, test)]
        return items

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

    def get_items(self, tree, test):
        items = {}
        if 'report' in tree:
            vulnerabilityTree = tree.get('report').get('vulnerabilities', [])
            for node in vulnerabilityTree:
                item = get_item(node, test)
                package_name = node.get('package_name')
                if len(package_name) > 64:
                    package_name = package_name[-64:]
                unique_key = node.get('name') + str(package_name + str(
                    node.get('package_version')) + str(node.get('severity')))
                items[unique_key] = item
        return list(items.values())


def get_item(vulnerability, test):
    severity = convert_severity(vulnerability.get('severity')) if 'severity' in vulnerability else "Info"
    vector = vulnerability.get('vectors_v3') if 'vectors_v3' in vulnerability else "CVSSv3 vector not provided. "
    fixed_version = vulnerability.get('fixed_version') if 'fixed_version' in vulnerability else "There seems to be no fix yet. Please check description field."
    score_v3 = vulnerability.get('score_v3') if 'score_v3' in vulnerability else "No CVSSv3 score yet."
    package_name = vulnerability.get('package_name')
    if len(package_name) > 64:
        package_name = package_name[-64:]
    description = vulnerability.get('description') if 'description' in vulnerability else ""
    link = vulnerability.get('link') if 'link' in vulnerability else ""

    # create the finding object
    finding = Finding(
        title=vulnerability.get('name') + ": " + package_name + " - " + vulnerability.get('package_version'),
        test=test,
        severity=severity,
        description=description + "<p> Vulnerable Package: " +
        package_name + "</p><p> Current Version: " + str(
            vulnerability['package_version']) + "</p>",
        mitigation=fixed_version.title(),
        references=link,
        component_name=package_name,
        component_version=vulnerability.get('package_version'),
        false_p=False,
        duplicate=False,
        out_of_scope=False,
        mitigated=None,
        severity_justification="{} (CVSS v3 base score: {})\n".format(vector, score_v3),
        impact=severity)
    finding.unsaved_vulnerability_ids = [vulnerability.get('name')]
    finding.description = finding.description.strip()

    return finding


# see neuvector/share/types.go
def convert_severity(severity):
    if severity.lower() == 'critical':
        return "Critical"
    elif severity.lower() == 'high':
        return "High"
    elif severity.lower() == 'medium':
        return "Medium"
    elif severity.lower() == 'low':
        return "Low"
    elif severity == '':
        return "Info"
    else:
        return severity.title()


class NeuVectorParser(object):

    def get_scan_types(self):
        return [NEUVECTOR_SCAN_NAME]

    def get_label_for_scan_types(self, scan_type):
        return NEUVECTOR_SCAN_NAME

    def get_description_for_scan_types(self, scan_type):
        return "JSON output of /v1/scan/{entity}/{id} endpoint."

    def get_findings(self, filename, test):
        if filename is None:
            return list()

        if filename.name.lower().endswith('.json'):
            return NeuVectorJsonParser().parse(filename, test)
        else:
            raise Exception('Unknown File Format')
