import hashlib
from xml.dom import NamespaceErr

from defusedxml import ElementTree as ET

from dojo.models import Endpoint, Finding

__author__ = 'dr3dd589'


class Severityfilter():
    def __init__(self):
        self.severity_mapping = {'4': 'Info',
                                 '3': 'Low',
                                 '2': 'Medium',
                                 '1': 'High'
                                 }
        self.severity = None

    def eval_column(self, column_value):
        if column_value in list(self.severity_mapping.keys()):
            self.severity = self.severity_mapping[column_value]
        else:
            self.severity = 'Info'


class WapitiParser(object):

    def get_scan_types(self):
        return ["Wapiti Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Wapiti Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import XML report"

    def get_findings(self, file, test):

        if file is None:
            return list()

        tree = ET.parse(file)
        # get root of tree.
        root = tree.getroot()
        # check if it is
        if 'report' not in root.tag:
            raise NamespaceErr("This doesn't seem to be a valid Wapiti xml file.")

        dupes = dict()
        for result in root.findall('report/results/result'):
            family = result.find('nvt/family').text
            # check if vulnerability found in family then proceed.
            if "vulnerability" in family:
                # get host
                host = result.find('host').text
                port = int(result.find('port').text)
                # get title
                title = result.find('nvt/name').text
                # get cve
                cve = result.find('nvt/cve').text
                # get numerical severity.
                num_severity = result.find('nvt/risk_factor').text
                severityfilter = Severityfilter()
                severityfilter.eval_column(num_severity)
                severity = severityfilter.severity
                # get reference
                reference = result.find('nvt/xref').text
                # get description and encode to utf-8.
                description = (result.find('description').text)
                mitigation = "N/A"
                impact = "N/A"
                # make dupe hash key
                dupe_key = hashlib.md5(str(description + title + severity).encode('utf-8')).hexdigest()
                # check if dupes are present.
                if dupe_key in dupes:
                    finding = dupes[dupe_key]
                    if finding.description:
                        finding.description = finding.description
                    self.process_endpoints(finding, host, port)
                    dupes[dupe_key] = finding
                else:
                    dupes[dupe_key] = True

                    finding = Finding(title=title,
                                    test=test,
                                    active=False,
                                    verified=False,
                                    cve=cve,
                                    description=description,
                                    severity=severity,
                                    numerical_severity=Finding.get_numerical_severity(
                                        severity),
                                    mitigation=mitigation,
                                    impact=impact,
                                    references=reference,
                                    dynamic_finding=True)

                    dupes[dupe_key] = finding
                    self.process_endpoints(finding, host, port)

        return list(dupes.values())

    def process_endpoints(self, finding, host, port):
        endpoint = Endpoint.objects.get_or_create(
            host=host,
            port=port
        )
        if endpoint not in finding.unsaved_endpoints:
            finding.unsaved_endpoints.append(endpoint)
