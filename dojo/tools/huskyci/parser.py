import hashlib
import json

from dojo.models import Finding


class HuskyCIParser(object):
    """
    Read JSON data from huskyCI compatible format and import it to DefectDojo
    """

    def get_scan_types(self):
        return ["HuskyCI Report"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import HuskyCI Report vulnerabilities in JSON format."

    def get_findings(self, json_output, test):

        if json_output is None:
            return

        tree = self.parse_json(json_output)
        if tree:
            return self.get_items(tree, test)

    def parse_json(self, json_output):
        try:
            data = json_output.read()
            try:
                tree = json.loads(str(data, 'utf-8'))
            except:
                tree = json.loads(data)
        except:
            raise ValueError("Invalid format")

        return tree

    def get_items(self, tree, test):
        items = {}

        for language in tree.get('huskyciresults', {}):
            tools_results = tree['huskyciresults'][language]
            for tool in tools_results:
                severity_results = tools_results[tool]
                for severity in severity_results:
                    vulns = severity_results[severity]
                    for vuln in vulns:
                        vuln['severity'] = severity[0:-5].lower().capitalize()
                        if vuln['severity'] not in ('High', 'Medium', 'Low'):
                            continue
                        unique_key = hashlib.md5(
                            str(vuln).encode('utf-8')).hexdigest()
                        item = get_item(vuln, test)
                        items[unique_key] = item

        return list(items.values())


def get_item(item_node, test):
    # description
    description = item_node.get('details', '')
    if 'code' in item_node:
        description += "\nCode: " + item_node.get("code")
    if 'confidence' in item_node:
        description += "\nConfidence: " + item_node.get("confidence")
    if 'securitytool' in item_node:
        description += "\nSecurity Tool: " + item_node.get("securitytool")

    finding = Finding(
        title=item_node.get('title'),
        test=test,
        severity=item_node.get('severity'),
        description=description,
        mitigation='N/A',
        references='',
        false_p=False,
        duplicate=False,
        out_of_scope=False,
        mitigated=None,
        file_path=item_node.get("file"),
        line=item_node.get("line"),
        static_finding=True,
        dynamic_finding=False,
        impact="No impact provided")

    return finding
