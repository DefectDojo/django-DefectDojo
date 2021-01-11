import hashlib
import json
from dojo.models import Finding

__author__ = 'mohcer'


class ScantistJSONParser(object):
    def __init__(self, file, test):
        self.items = []

        if file is None:
            return

        result_data = file.read()
        try:
            content = json.loads(str(result_data, 'utf-8'))
        except:
            content = json.loads(result_data)

        if content is None:
            return

        self.items = [data for data in self.get_items(content, test)]

    def get_items(self, tree, test):
        """
        tree list: input tree list of all the vulnerability findings
        test:
        : purpose: parses input rawto extract dojo
        """
        def get_findings(vuln, test):
            """
            vuln : input vulnerable node
            test :
            """
            cve = vuln.get("Public ID")
            component_name = vuln.get("Library")
            component_version = vuln.get("Library Version")

            title = cve + '|' + component_name
            description = vuln.get("Description")

            file_path = vuln.get("File Path", "")
            sourcefile = None

            severity = vuln.get("Score", "N/A")
            score = vuln.get("cvss_v3_score", "N/A")

            mitigation = vuln.get("Patched Version")

            finding = Finding(
                title=title,
                test=test,
                description=description,
                severity=severity,
                cve=cve,
                cwe=vuln.get('cwe'),
                mitigation=mitigation,
                numerical_severity=Finding.get_numerical_severity(
                                  vuln.get('Score')),
                references=vuln.get('references'),
                file_path=file_path,
                component_name=component_name,
                component_version=component_version,
                severity_justification=vuln.get('severity_justification'),
                dynamic_finding=True
            )

            return finding

        items = dict()
        for node in tree:
            item = get_findings(node, test)

            if item:
                hash_key = hashlib.md5(
                    node.get('Public ID').encode('utf-8') + node.get('Library').encode('utf-8')).hexdigest()

                items[hash_key] = get_findings(node, test)

        return list(items.values())
