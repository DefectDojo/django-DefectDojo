import json

from dojo.models import Endpoint, Finding
from django.utils.dateparse import parse_datetime


class StackHawkScanMetadata:
    def __init__(self, completed_scan):
        self.date = completed_scan['scan']['startedTimestamp']
        self.component_name = completed_scan['scan']['application']
        self.component_version = completed_scan['scan']['env']
        self.active = True
        self.verified = True
        self.static_finding = False
        self.dynamic_finding = True
        self.service = completed_scan['scan']['application']


class StackHawkParser(object):
    """
    DAST findings from StackHawk
    """

    def get_scan_types(self):
        return ["StackHawk HawkScan"]

    def get_label_for_scan_types(self, scan_type):
        return "StackHawk HawkScan"

    def get_description_for_scan_types(self, scan_type):
        return "StackHawk webhook event can be imported in JSON format."

    def get_findings(self, json_output, test):
        completed_scan = self.__parse_json(json_output)

        metadata = StackHawkScanMetadata(completed_scan)
        findings = self.__extract_findings(completed_scan, metadata, test)

        return findings

    def __extract_findings(self, completed_scan, metadata: StackHawkScanMetadata, test):
        findings = {}

        if 'findings' in completed_scan:
            raw_findings = completed_scan['findings']

            for raw_finding in raw_findings:
                key = raw_finding['pluginId']
                if key not in findings:
                    finding = self.__extract_finding(raw_finding, metadata, test)
                    findings[key] = finding

        # Update the test description these scan results are linked to.
        test.description = 'View scan details here: ' + self.__hyperlink(completed_scan['scan']['scanURL'])

        return list(findings.values())

    def __extract_finding(self, raw_finding, metadata: StackHawkScanMetadata, test) -> Finding:

        steps_to_reproduce = "Use a specific message link and click 'Validate' to see the cURL!\n\n"

        host = raw_finding['host']
        endpoints = []

        for path in raw_finding['paths']:
            steps_to_reproduce += '**' + path['path'] + '**\n' + self.__hyperlink(path['pathURL']) + '\n'
            endpoint = Endpoint.from_uri(host + path['path'])
            endpoints.append(endpoint)

        finding = Finding(
            test=test,
            title=raw_finding['pluginName'],
            date=parse_datetime(metadata.date),
            severity=raw_finding['severity'],
            description="View this finding in the StackHawk platform at:\n" +
                        self.__hyperlink(raw_finding['findingURL']),
            steps_to_reproduce=steps_to_reproduce,
            active=metadata.active,
            verified=metadata.verified,
            numerical_severity=self.__convert_severity(raw_finding['severity']),
            component_name=metadata.component_name,
            component_version=metadata.component_version,
            static_finding=metadata.static_finding,
            dynamic_finding=metadata.dynamic_finding,
            vuln_id_from_tool=raw_finding['pluginId'],
            nb_occurences=raw_finding['totalCount'],
            service=metadata.service
        )

        finding.unsaved_endpoints.extend(endpoints)
        return finding

    @staticmethod
    def __parse_json(json_output):
        report = json.load(json_output)

        if not report['scanCompleted'] or report['service'] != 'StackHawk':
            # By verifying the json data, we can now make certain assumptions.
            # Specifically, that the attributes accessed when parsing the finding will always exist.
            # See our documentation for more details on this data:
            # https://docs.stackhawk.com/workflow-integrations/webhook.html#scan-completed
            raise Exception(" Unexpected JSON format provided. "
                            "Need help? "
                            "Check out the StackHawk Docs at "
                            "https://docs.stackhawk.com/workflow-integrations/defect-dojo.html"
                            )

        return report['scanCompleted']

    @staticmethod
    def __convert_severity(severity):
        """Convert severity value"""
        if severity == 'Low':
            return 3
        elif severity == 'Medium':
            return 2
        elif severity == 'High':
            return 1
        else:
            return 4

    @staticmethod
    def __hyperlink(link: str) -> str:
        return '[' + link + '](' + link + ')'
