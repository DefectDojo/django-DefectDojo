import hashlib
import json
from urllib.parse import urlparse
from dojo.models import Endpoint, Finding
from datetime import datetime

class KubeHunterParser(object):
    """
    kube-hunter hunts for security weaknesses in Kubernetes clusters. The tool was developed to increase awareness and visibility for security issues in Kubernetes environments.
    """

    def get_scan_types(self):
        return ["KubeHunter Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "KubeHunter Scan"

    def get_description_for_scan_types(self, scan_type):
        return "KubeHunter JSON vulnerability report format.."

    def get_findings(self, file, test):
        data = json.load(file)

        dupes = dict()

        # Find any missing attribute
        vulnerabilities = data['vulnerabilities']
        check_required_attributes(vulnerabilities)

        for item in vulnerabilities:
            vulnerability_id = item.get('vid')
            title = item['vulnerability']

            # Finding details information
            findingdetail = '**Hunter**: ' + item.get('hunter') + '\n\n'
            findingdetail += '**Category**: ' + item.get('category') + '\n\n'
            findingdetail += '**Location**: ' + item.get('location') + '\n\n'
            findingdetail += '**Description**:\n' + item.get('description') + '\n\n'
            
            # Finding severity
            severity = item.get('severity', 'info')
            allowed_severity = ['info','low','medium','high',"critical"]
            if severity.lower() in allowed_severity:
                severity = severity.capitalize()
            else :
                severity = 'Info'

            # Finding mitigation and reference
            avd_reference = item.get('avd_reference')

            if avd_reference and avd_reference != '' and vulnerability_id != 'None' :
                mitigation = f"Further details can be found in kube-hunter documentation available at : {avd_reference}"
                references = "**Kube-hunter AVD reference**: "+avd_reference
            else:
                mitigation = ''
                references = ''

            # Finding evidence
            evidence = item.get('evidence')
            steps_to_reproduce = 'No evidence provided.'
            if evidence and evidence != '' and evidence != 'none' :
                steps_to_reproduce += '**Evidence**: ' + item.get('evidence')

            finding = Finding(
                title=title,
                test=test,
                description=findingdetail,
                severity=severity,
                mitigation=mitigation,
                references=references,
                static_finding=False,
                dynamic_finding=True,
                duplicate=False,
                out_of_scope=False,
                vuln_id_from_tool=vulnerability_id,
                steps_to_reproduce=steps_to_reproduce
            )

            # internal de-duplication
            dupe_key = hashlib.sha256(str(finding.description + finding.title + finding.steps_to_reproduce + finding.vuln_id_from_tool).encode('utf-8')).hexdigest()

            if dupe_key not in dupes:
                dupes[dupe_key] = finding

        return list(dupes.values())
    
def check_required_attributes(vulnerabilities):
    required_attributes = ["hunter", "category", "location", "description", "evidence", "avd_reference", "severity"]

    missing_vulnerabilities = []

    for idx, vulnerability in enumerate(vulnerabilities, start=1):
        missing_attributes = [attr for attr in required_attributes if attr not in vulnerability]

        if missing_attributes:
            missing_vulnerabilities.append(f"Vulnerability {idx}: Missing attributes: {', '.join(missing_attributes)}")
    
    if missing_vulnerabilities:
        raise ValueError("\n`".join(missing_vulnerabilities))