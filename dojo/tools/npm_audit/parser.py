import json

from dojo.models import Finding


class NpmAuditParser(object):
    def __init__(self, json_output, test):

        tree = self.parse_json(json_output)

        if tree:
            self.items = [data for data in self.get_items(tree, test)]
        else:
            self.items = []

    def parse_json(self, json_output):
        if json_output is None:
            self.items = []
            return
        try:
            data = json_output.read()
            try:
                tree = json.loads(str(data, 'utf-8'))
            except:
                tree = json.loads(data)
            subtree = tree.get('advisories')
        except:
            raise Exception("Invalid format")

        return subtree

    def get_items(self, tree, test):
        items = {}

        for key, node in tree.items():
            item = get_item(node, test)
            unique_key = str(node['id']) + str(node['module_name'])
            items[unique_key] = item

        return list(items.values())


def get_item(item_node, test):

    if item_node['severity'] == 'low':
        severity = 'Low'
    elif item_node['severity'] == 'moderate':
        severity = 'Medium'
    elif item_node['severity'] == 'high':
        severity = 'High'
    elif item_node['severity'] == 'critical':
        severity = 'Critical'
    else:
        severity = 'Info'

    finding = Finding(title=item_node['title'] + " - " + "(" + item_node['module_name'] + ", " + item_node['vulnerable_versions'] + ")",
                      test=test,
                      severity=severity,
                      description=item_node['overview'] + "\n Vulnerable Module: " +
                      item_node['module_name'] + "\n Vulnerable Versions: " +
                      str(item_node['vulnerable_versions']) + "\n Patched Version: " +
                      str(item_node['patched_versions']) + "\n Vulnerable Path: " + str(item_node['findings'][0]['paths']) + "\n CWE: " +
                      str(item_node['cwe']) + "\n Access: " +
                      str(item_node['access']),
                      cwe=item_node['cwe'][4:],
                      mitigation=item_node['recommendation'],
                      references=item_node['url'],
                      active=False,
                      verified=False,
                      false_p=False,
                      duplicate=False,
                      out_of_scope=False,
                      mitigated=None,
                      impact="No impact provided")

    return finding
