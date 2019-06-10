import json
import hashlib

from dojo.models import Finding


class RetireJsParser(object):
    def __init__(self, json_output, test):
        self.target = None
        self.port = "80"
        self.host = None

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
            for result in node['results']:
                if 'vulnerabilities' in result:
                    for vulnerability in result['vulnerabilities']:
                        item = get_item(vulnerability, test, node['file'])
                        item.title += " (" + result['component'] + ", " + result['version'] + ")"
                        item.description += "\n\n Raw Result: " + str(json.dumps(vulnerability, indent=4, sort_keys=True))
                        unique_key = item.title + hashlib.md5(item.references).hexdigest() + hashlib.md5(node['file']).hexdigest()
                        items[unique_key] = item

        return list(items.values())


def get_item(item_node, test, file):
    title = ""

    if 'summary' in item_node['identifiers']:
        title = item_node['identifiers']['summary']
    elif 'CVE' in item_node['identifiers']:
        title = "".join(item_node['identifiers']['CVE'])
    elif 'osvdb' in item_node['identifiers']:
        title = "".join(item_node['identifiers']['osvdb'])

    finding = Finding(title=title,
                      test=test,
                      cwe=1035,  # Vulnerable Third Party Component
                      severity=item_node['severity'].title(),
                      description=title + "\n\n Affected File - " + file,
                      file_path=file,
                      mitigation="No Mitigation Provided",
                      references="\n\n".join(item_node['info']),
                      active=False,
                      verified=False,
                      false_p=False,
                      duplicate=False,
                      out_of_scope=False,
                      mitigated=None,
                      impact="No impact provided")

    return finding
