import json
from dojo.models import Finding


class HadolintParser(object):
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
        for node in tree:
            item = get_item(node, test)
            unique_key = str(node['line']) + "-" + str(node['column']) + node['code'] + node['file']
            items[unique_key] = item

        return items.values()


def get_item(vulnerability, test):
    if 'level' in vulnerability:
        # If we're dealing with a license finding, there will be no cvssScore
        if vulnerability['level'] == "error":
            severity = "Critical"
        elif vulnerability['level'] == "warning":
            severity = "High"
        else:
            severity = "Info"
    # TODO: some seem to not have anything. Needs UNKNOWN new status in the model. Some vuln do not yet have cvss assigned.
    else:
        severity = "Info"

    # create the finding object
    finding = Finding(
        title=vulnerability['code'] + ": " + vulnerability['file'],
        test=test,
        severity=severity,
        description=vulnerability['file'] + ":" + str(vulnerability['line']) + "   " + vulnerability['code'] + "  " + vulnerability['message'],
        mitigation="No mitigation provided",
        active=False,
        verified=False,
        false_p=False,
        duplicate=False,
        out_of_scope=False,
        mitigated=None,
        impact="No impact provided")

    finding.description = finding.description.strip()

    return finding
