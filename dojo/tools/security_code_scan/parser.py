import json
import re


from dojo.models import Finding

# Import Result of CLI from SecurityCode Scan
# https://github.com/security-code-scan/security-code-scan
# We need to pass --cwe to the scanner for the data to feed CWE in the report
class SecurityCodeScanParser(object):

    def get_scan_types(self):
        return ["Security Code Scan Report"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import Security Code Scan output (--cwe)"

    def get_findings(self, filename, test):



        return None


def get_num_sev(severity):
    if severity == 'Critical':
        return 'Critical'
    elif severity == 'High':
        return 'High'
    elif severity == 'Medium':
        return 'Meidum'
    elif severity == 'Low':
        return 'Low'
    else:
        return 'Info'

