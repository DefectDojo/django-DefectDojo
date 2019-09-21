import json

from dojo.models import Finding


class AquaJSONParser(object):
    def __init__(self, json_output, test):

        tree = self.parse_json(json_output)

        if tree:
            self.items = [data for data in self.get_items(tree, test)]
        else:
            self.items = []

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
        if 'resources' in tree:
            vulnerabilityTree = tree['resources']

            for node in vulnerabilityTree:
                resource = node.get('resource')
                vulnerabilities = node.get('vulnerabilities')

                for vuln in vulnerabilities:
                    item = get_item(resource, vuln, test)
                    if 'name' in vuln:
                        unique_key = resource.get('cpe') + vuln.get('name')
                    else:
                        unique_key = resource.get('cpe') + "None"

                    items[unique_key] = item

        return list(items.values())


def get_item(resource, vuln, test):
    if 'name' in resource:
        resource_name = resource.get('name')
    else:
        resource_name = resource.get('path')

    if 'version' in resource:
        resource_version = resource.get('version')
    else:
        resource_version = "No version"

    if 'name' in vuln:
        cve = vuln.get('name')
    else:
        cve = "No CVE"

    if 'fix_version' in vuln:
        fix_version = vuln['fix_version']
    else:
        fix_version = "None"

    if 'description' in vuln:
        description = vuln.get('description')
    else:
        description = "No description."

    url = ""
    if 'nvd_url' in vuln:
        url += "\n{}".format(vuln.get('nvd_url'))
    if 'vendor_url' in vuln:
        url += "\n{}".format(vuln.get('vendor_url'))

    # Take in order of preference (most prio at the bottom of ifs), and put everything in severity justification anyways.
    score = 0
    severity_justification = ""
    used_for_classification = ""
    if 'aqua_score' in vuln:
        score = vuln.get('aqua_score')
        used_for_classification = "Aqua score ({}) used for classification.\n".format(score)
    if 'vendor_score' in vuln:
        score = vuln.get('vendor_score')
        used_for_classification = "Vendor score ({}) used for classification.\n".format(score)
    if 'nvd_score' in vuln:
        score = vuln.get('nvd_score')
        used_for_classification = "NVD score v2 ({}) used for classification.\n".format(score)
        severity_justification += "\nNVD v2 vectors: {}".format(vuln.get('nvd_vectors'))
    if 'nvd_score_v3' in vuln:
        score = vuln.get('nvd_score_v3')
        used_for_classification = "NVD score v3 ({}) used for classification.\n".format(score)
        severity_justification += "\nNVD v3 vectors: {}".format(vuln.get('nvd_vectors_v3'))
    severity_justification += "\n{}".format(used_for_classification)

    if score == 0:
        severity = "Info"
    elif score <= 3.9:
        severity = "Low"
    elif score > 4.0 and score <= 6.9:
        severity = "Medium"
    elif score > 7.0 and score <= 8.9:
        severity = "High"
    else:
        severity = "Critical"

    finding = Finding(
        title=cve + " - " + resource_name + " (" + resource_version + ") ",
        test=test,
        severity=severity,
        severity_justification=severity_justification,
        cwe=0,
        cve=cve,
        description=description,
        mitigation=fix_version,
        references=url,
        impact=severity)

    finding.description = finding.description.strip()
    return finding
