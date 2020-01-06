import json
import re
from dojo.models import Finding


class NodeJSParser(object):
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
        skip_nodes = ['files', 'vuln_count', 'total_count']
        for node in tree:
            if node not in skip_nodes:
                for vuln_cat in tree[node]:
                    for vuln in tree[node][vuln_cat]:
                        item = get_item(vuln, test)
                        unique_key = item.title
                        items[unique_key] = item

        return list(items.values())


def get_item(item_node, test):

    file_name = item_node.get('filename', '')
    line_number = item_node.get('line', 0)
    lines = item_node.get('lines', '')
    path = item_node.get('path', '')
    title = item_node.get('title', '')
    description = item_node.get('description', '')
    impact = 'See description'
    sha = item_node.get('sha2', '')
    tag = item_node.get('tag', '')
    static_finding = False if tag == 'web' else True
    mitigation = 'Follow intstructions in description'
    
    # The variable lines contains the actual code where the vuln is located.
    # Due to non standard characeters, it is being left out for now.
    # if len(lines) > 0:
    #     mitigation += ' at ' + path + 'in the following code block:\n' + lines

    references = ''
    if len(sha) > 0:
        references += 'hash: ' + sha

    finding = Finding(title=title,
                      test=test,
                      severity='Low',
                      description=description,
                      mitigation=mitigation,
                      references=references,
                      static_finding=static_finding,
                      dynamic_finding=not static_finding,
                      active=False,
                      verified=False,
                      false_p=False,
                      duplicate=False,
                      out_of_scope=False,
                      mitigated=None,
                      impact=impact)

    if len(file_name) > 0 and line_number > 0:
        finding.title += ' - ' + file_name + ':' + str(line_number)
        finding.line = line_number
        finding.file_path = path

    return finding
