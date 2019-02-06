import json
import logging


from dojo.models import Finding


logger = logging.getLogger(__name__)


class ClairKlarParser(object):
    def __init__(self, json_output, test):

        tree = self.parse_json(json_output)

        self.items = []
        clair_severities = ["Unknown", "Negligible", "Low", "Medium", "High", "Critical", "Defcon1"]
        if tree:
            for clair_severity in clair_severities:
                self.set_items_for_severity(tree, test, clair_severity)

    def parse_json(self, json_output):
        try:
            tree = json.load(json_output)
            subtree = tree.get('Vulnerabilities')
        except:
            raise Exception("Invalid format")

        return subtree

    def set_items_for_severity(self, tree, test, severity):
        tree_severity = tree.get(severity)
        if tree_severity:
            for data in self.get_items(tree_severity, test):
                self.items.append(data)
            logger.info("Appended findings for severity " + severity)
        else:
            logger.info("No findings for severity " + severity)

    def get_items(self, tree_severity, test):
        items = {}

        for node in tree_severity:
            item = get_item(node, test)
            unique_key = str(node['Name']) + str(node['FeatureName'])
            items[unique_key] = item

        return items.values()


def get_item(item_node, test):

    if item_node['Severity'] == 'Negligible':
        severity = 'Info'
    elif item_node['Severity'] == 'Unknown':
        severity = 'Critical'
    elif item_node['Severity'] == 'Defcon1':
        severity = 'Critical'
    else:
        severity = item_node['Severity']

    finding = Finding(title=item_node['Name'] + " - " + "(" + item_node['FeatureName'] + ", " + item_node['FeatureVersion'] + ")",
                      test=test,
                      severity=severity,
                      description=item_node['Description'] + "\n Vulnerable feature: " +
                                  item_node['FeatureName'] + "\n Vulnerable Versions: " +
                                  str(item_node['FeatureVersion']) + "\n Fixed by: " +
                                  str(item_node['FixedBy']) + "\n Namespace: " + str(item_node['NamespaceName']) + "\n CVE: " +
                                  str(item_node['Name']),
                      mitigation="Please use version " + item_node['FixedBy'] + " of library " + item_node['FeatureName'],
                      references=item_node['Link'],
                      active=False,
                      verified=False,
                      false_p=False,
                      duplicate=False,
                      out_of_scope=False,
                      mitigated=None,
                      cwe=1035,  # Vulnerable Third Party Component
                      impact="No impact provided")

    return finding
