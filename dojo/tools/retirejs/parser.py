import hashlib
import json

from dojo.models import Finding


class RetireJsParser(object):

    def get_scan_types(self):
        return ["Retire.js Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Retire.js Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Retire.js JavaScript scan (--js) output file can be imported in JSON format."

    def get_findings(self, json_output, test):
        tree = json.load(json_output)
        return self.get_items(tree, test)

    def get_items(self, tree, test):
        items = {}
        if 'data' in tree:
            tree = tree['data']
        for node in tree:
            for result in node['results']:
                if 'vulnerabilities' in result:
                    for vulnerability in result['vulnerabilities']:
                        item = self.get_item(vulnerability, test, node['file'])
                        item.title += " (" + result['component'] + ", " + result['version'] + ")"
                        item.description += "\n\n Raw Result: " + str(json.dumps(vulnerability, indent=4, sort_keys=True))
                        item.references = item.references

                        item.component_name = result.get('component')
                        item.component_version = result.get('version')
                        item.file_path = node['file']

                        encrypted_file = node['file']
                        unique_key = hashlib.md5((item.title + item.references + encrypted_file).encode()).hexdigest()
                        items[unique_key] = item
        return list(items.values())

    def get_item(self, item_node, test, file):
        title = ""
        if 'identifiers' in item_node:
            if 'summary' in item_node['identifiers']:
                title = item_node['identifiers']['summary']
            elif 'CVE' in item_node['identifiers']:
                title = "".join(item_node['identifiers']['CVE'])
            elif 'osvdb' in item_node['identifiers']:
                title = "".join(item_node['identifiers']['osvdb'])

        finding = Finding(
            title=title,
            test=test,
            cwe=1035,  # Vulnerable Third Party Component
            severity=item_node['severity'].title(),
            description=title + "\n\n Affected File - " + file,
            file_path=file,
            references="\n".join(item_node['info']),
            false_p=False,
            duplicate=False,
            out_of_scope=False,
        )

        return finding
