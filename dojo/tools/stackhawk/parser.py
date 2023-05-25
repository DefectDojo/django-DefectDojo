import json

from dojo.models import Endpoint, Finding
from django.utils.dateparse import parse_datetime


class StackHawkScanMetadata:
    def __init__(self, completed_scan):
        self.date = completed_scan['scan']['startedTimestamp']
        self.component_name = completed_scan['scan']['application']
        self.component_version = completed_scan['scan']['env']
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

        paths = raw_finding['paths']
        for path in paths:
            steps_to_reproduce += '**' + path['path'] + '**' +\
                                  self.__endpoint_status(path['status']) +\
                                  '\n' + self.__hyperlink(path['pathURL']) + '\n'
            endpoint = Endpoint.from_uri(host + path['path'])
            endpoints.append(endpoint)

        are_all_endpoints_risk_accepted = self.__are_all_endpoints_in_status(paths, 'RISK_ACCEPTED')
        are_all_endpoints_false_positive = self.__are_all_endpoints_in_status(paths, 'FALSE_POSITIVE')

        finding = Finding(
            test=test,
            title=raw_finding['pluginName'],
            date=parse_datetime(metadata.date),
            severity=raw_finding['severity'],
            description="View this finding in the StackHawk platform at:\n" +
                        self.__hyperlink(raw_finding['findingURL']),
            steps_to_reproduce=steps_to_reproduce,
            component_name=metadata.component_name,
            component_version=metadata.component_version,
            static_finding=metadata.static_finding,
            dynamic_finding=metadata.dynamic_finding,
            vuln_id_from_tool=raw_finding['pluginId'],
            nb_occurences=raw_finding['totalCount'],
            service=metadata.service,
            false_p=are_all_endpoints_false_positive,
            risk_accepted=are_all_endpoints_risk_accepted
        )

        finding.unsaved_endpoints.extend(endpoints)
        return finding

    @staticmethod
    def __parse_json(json_output):
        report = json.load(json_output)

        if 'scanCompleted' not in report or 'service' not in report or report['service'] != 'StackHawk':
            # By verifying the json data, we can now make certain assumptions.
            # Specifically, that the attributes accessed when parsing the finding will always exist.
            # See our documentation for more details on this data:
            # https://docs.stackhawk.com/workflow-integrations/webhook.html#scan-completed
            raise ValueError(" Unexpected JSON format provided. "
                             "Need help? "
                             "Check out the StackHawk Docs at "
                             "https://docs.stackhawk.com/workflow-integrations/defect-dojo.html"
                             )

        return report['scanCompleted']

    @staticmethod
    def __hyperlink(link: str) -> str:
        return '[' + link + '](' + link + ')'

    @staticmethod
    def __endpoint_status(status: str) -> str:
        if status == 'NEW':
            return '** - New**'
        elif status == 'RISK_ACCEPTED':
            return '** - Marked "Risk Accepted"**'
        elif status == 'FALSE_POSITIVE':
            return '** - Marked "False Positive"**'
        else:
            return ""

    @staticmethod
    def __are_all_endpoints_in_status(paths, check_status: str) -> bool:
        return all(item['status'] == check_status for item in paths)
