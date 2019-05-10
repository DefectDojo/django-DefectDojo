import json
from dojo.models import Finding


class TwistlockParser(object):
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
        if 'results' in tree:
            vulnerabilityTree = tree['results'][0]['vulnerabilities']

            for node in vulnerabilityTree:

                item = get_item(node, test)
                unique_key = node['id'] + str(node['packageName'] + str(
                    node['packageVersion']) + str(node['severity']))
                items[unique_key] = item

        return items.values()


def get_item(vulnerability, test):
    # Following the CVSS Scoring per https://nvd.nist.gov/vuln-metrics/cvss
    if 'cvss' in vulnerability:
        # If we're dealing with a license finding, there will be no cvssScore
        if vulnerability['cvss'] <= 3.9:
            severity = "Low"
        elif vulnerability['cvss'] > 4.0 and vulnerability['cvss'] <= 6.9:
            severity = "Medium"
        elif vulnerability['cvss'] > 7.0 and vulnerability['cvss'] <= 8.9:
            severity = "High"
        else:
            severity = "Critical"
    # TODO: some seem to not have anything. Needs UNKNOWN new status in the model. Some vuln do not yet have cvss assigned.
    else:
        severity = "Info"

    vector = vulnerability['vector'] if 'vector' in vulnerability else "CVSS vector not provided. "
    status = vulnerability['status'] if 'status' in vulnerability else "There seems to be no fix yet. Please check description field."
    cvss = vulnerability['cvss'] if 'cvss' in vulnerability else "No CVSS score yet."

    # create the finding object
    finding = Finding(
        title=vulnerability['id'] + ": " + vulnerability['packageName'] + " - " + vulnerability['packageVersion'],
        test=test,
        severity=severity,
        description=vulnerability['description'] + "<p> Vulnerable Package: " +
        vulnerability['packageName'] + "</p><p> Current Version: " + str(
            vulnerability['packageVersion']) + "</p>",
        mitigation=status,
        references=vulnerability['link'],
        active=False,
        verified=False,
        false_p=False,
        duplicate=False,
        out_of_scope=False,
        mitigated=None,
        severity_justification="{}({})\n\n{}".format(vector, cvss, vulnerability['riskFactors']),
        impact=severity)

    finding.description = finding.description.strip()

    return finding
