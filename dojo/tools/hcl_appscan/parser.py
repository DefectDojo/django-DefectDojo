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
                title = ""
                description = ""
                for item in finding:
                    match item.tag:
                        case 'severity':
                            severity = item.text.capitalize()
                        case 'cwe':
                            cwe = item.text
                        case 'remediation':
                            remediation = item.text
                        case 'advisory':
                            advisory = item.text
                        case 'issue-type':
                            title = item.text
                            issuetypename = item.text
                            description = description + "Issue-Type-Name: " + issuetypename + "\n"
                        case 'issue-type-name':
                            title = item.text
                            issuetypename = item.text
                            description = description + "Issue-Type-Name: " + issuetypename + "\n"
                        case 'location':
                            location = item.text
                            description = description + "Location: " + location + "\n"
                        case 'domain':
                            title += "_" + item.text
                            domain = item.text
                            description = description + "Domain: " + domain + "\n"
                        case 'url-name':
                            title += "_" + item.text
                            urlname = item.text
                            description = description + "Url-Name: " + urlname + "\n"
                        case 'element':
                            element = item.text
                            description = description + "Element: " + element + "\n"
                        case 'element-type':
                            elementtype = item.text
                            description = description + "ElementType: " + elementtype + "\n"
                        case 'path':
                            title += "_" + item.text
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
                finding = Finding(
                    title=title,
                    description=description,
                    severity=severity,
                    cwe=cwe,
                    mitigation="Remediation: " + remediation + "\nAdvisory: " + advisory,
                    dynamic_finding=True,
                    static_finding=False,
                )
                findings.append(finding)
                try:
                    finding.unsaved_endpoints = list()
                    endpoint = Endpoint(host=host, port=port)
                    finding.unsaved_endpoints.append(endpoint)
                except UnboundLocalError:
                    pass
            return findings
        else:
            return findings
