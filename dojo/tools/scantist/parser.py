import hashlib
import json

from dojo.models import Finding


class ScantistParser(object):
    """
    Scantist Parser: Scantist does a deep scan of source code and binaries for vulnerabilities and has reports
    following three main categories
    - Components (primary components from dependency graph)
    - Vulnerabilities (Security Issues)
    - Compliance (policies and its violations)

    This parser primarily focuses on Vulnerability report and the risks identified in JSON format.
    @todo: other format will be available soon.

    Website: https://scantist.com/
    """

    def get_scan_types(self):
        return ["Scantist Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Scantist Dependency Scanning Report vulnerabilities in JSON format."

    def get_findings(self, file, test):
        tree = json.load(file)
        return self.get_items(tree, test)

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
            vulnerability_id = vuln.get("Public ID")
            # default use OWASP a9 until the Scantist output report includes
            cwe = 1035

            component_name = vuln.get("Library")
            component_version = vuln.get("Library Version")

            title = vulnerability_id + '|' + component_name
            description = vuln.get("Description")

            file_path = vuln.get("File Path", "")

            severity = vuln.get("Score", "Info")

            mitigation = vuln.get("Patched Version")

            finding = Finding(
                title=title,
                test=test,
                description=description,
                severity=severity,
                cwe=cwe,
                mitigation=mitigation,
                references=vuln.get('references'),
                file_path=file_path,
                component_name=component_name,
                component_version=component_version,
                severity_justification=vuln.get('severity_justification'),
                dynamic_finding=True
            )
            if vulnerability_id:
                finding.unsaved_vulnerability_ids = [vulnerability_id]
            return finding

        items = dict()
        for node in tree:
            item = get_findings(node, test)

            if item:
                hash_key = hashlib.md5(
                    node.get('Public ID').encode('utf-8') + node.get('Library').encode('utf-8')).hexdigest()

                items[hash_key] = get_findings(node, test)

        return list(items.values())
