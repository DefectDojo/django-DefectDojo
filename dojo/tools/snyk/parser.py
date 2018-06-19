import json

from dojo.models import Finding


class SnykParser(object):
    def __init__(self, json_output, test):

        tree = self.parse_json(json_output)

        if tree:
            self.items = [data for data in self.get_items(tree, test)]
        else:
            self.items = []

    def parse_json(self, json_output):
        try:
            tree = json.load(json_output)
        except:
            raise Exception("Invalid format")

        return tree

    def get_items(self, tree, test):
        items = {}
        if 'vulnerabilities' in tree:
            vulnerabilityTree = tree['vulnerabilities']

            for node in vulnerabilityTree:

                item = get_item(node, test)
                unique_key = node['title'] + str(node['packageName'] + str(
                    node['version']) + str(node['from']))
                items[unique_key] = item

        return items.values()


def get_item(vulnerability, test):

    # vulnerable and unaffected versions can be in string format for a single vulnerable version, or an array for multiple versions depending on the language.
    if isinstance(vulnerability['semver']['vulnerable'], list):
        vulnerable_versions = ", ".join(vulnerability['semver']['vulnerable'])
    else:
        vulnerable_versions = vulnerability['semver']['vulnerable']

    # Following the CVSS Scoring per https://nvd.nist.gov/vuln-metrics/cvss
    if vulnerability['cvssScore'] <= 3.9:
        severity = "Low"
    elif vulnerability['cvssScore'] > 4.0 and vulnerability['cvssScore'] <= 6.9:
        severity = "Medium"
    elif vulnerability['cvssScore'] > 7.0 and vulnerability['cvssScore'] <= 8.9:
        severity = "High"
    else:
        severity = "Critical"

    # create the finding object
    finding = Finding(
        title=vulnerability['from'][0] + ": " + vulnerability['title'] + " - " + "(" + vulnerability['packageName'] + ", " + vulnerability['version'] + ")",
        test=test,
        severity=severity,
        cwe=1035,  # Vulnerable Third Party Component
        description=vulnerability['description'] + "\n Vulnerable Package: " +
        vulnerability['packageName'] + "\n Current Version: " + str(
            vulnerability['version']) + "\n Vulnerable Version(s): " +
        vulnerable_versions + "\n Vulnerable Path: " + " > ".join(
            vulnerability['from']),
        mitigation="A fix (if available) will be provided in the description.",
        references="Provided in the description.",
        active=False,
        verified=False,
        false_p=False,
        duplicate=False,
        out_of_scope=False,
        mitigated=None,
        impact=severity)

    return finding
