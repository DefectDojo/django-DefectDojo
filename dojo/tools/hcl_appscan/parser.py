from xml.dom import NamespaceErr
from defusedxml import ElementTree as ET
from dojo.models import Finding, Endpoint


class HCLAppScanParser(object):
    def get_scan_types(self):
        return ["HCLAppScan XML"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import XML output of HCL AppScan."

    def get_findings(self, file, test):
        findings = []
        tree = ET.parse(file)
        root = tree.getroot()
        if "xml-report" not in root.tag:
            raise NamespaceErr(
                "This doesn't seem to be a valid HCLAppScan xml file."
            )
        report = root.find("issue-group")
        if report is not None:
            for finding in report:
                description = ""
                for item in finding:
                    match item.tag:
                        case 'severity':
                            severity = item.text
                        case 'cwe':
                            cwe = item.text
                        case 'remediation':
                            remediation = item.text
                        case 'advisory':
                            advisory = item.text
                        case 'issue-type-name':
                            issuetypename = item.text
                            description = description + "Issue-Type-Name: " + issuetypename + "\n"
                        case 'location':
                            location = item.text
                            description = description + "Location: " + location + "\n"
                        case 'domain':
                            domain = item.text
                            description = description + "Domain: " + domain + "\n"
                        case 'element':
                            element = item.text
                            description = description + "Element: " + element + "\n"
                        case 'element-type':
                            elementtype = item.text
                            description = description + "ElementType: " + elementtype + "\n"
                        case 'path':
                            path = item.text
                            description = description + "Path: " + path + "\n"
                        case 'scheme':
                            scheme = item.text
                            description = description + "Scheme: " + scheme + "\n"
                        case 'host':
                            host = item.text
                            description = description + "Host: " + host + "\n"
                        case 'port':
                            port = item.text
                            description = description + "Port: " + port + "\n"
                        case 'asoc-issue-id':
                            asocissueid = item.text
                finding = Finding(
                    title=str(issuetypename + "_" + domain + "_" + path),
                    description=description,
                    severity=severity,
                    cwe=cwe,
                    mitigation="Remediation: " + remediation + "\nAdvisory: " + advisory,
                    dynamic_finding=True,
                    static_finding=False,
                    unique_id_from_tool=asocissueid
                )
                findings.append(finding)
                finding.unsaved_endpoints = list()
                endpoint = Endpoint(host=host, port=port)
                finding.unsaved_endpoints.append(endpoint)
            return findings
        else:
            return findings
