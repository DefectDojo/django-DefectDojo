import json

from dojo.models import Endpoint, Finding
from django.utils.dateparse import parse_datetime


class HydraScanMetadata:
    def __init__(self, generator):
        self.date = generator['built']
        self.command = generator['commandline']
        self.schema_version = generator['jsonoutputversion']
        self.static_finding = False
        self.dynamic_finding = True
        self.service_type = generator['service']
        self.tool_version = generator['version']
        self.server = generator['server']

class HydraParser(object):
    """
    Weak password findings from THC-Hydra (https://github.com/vanhauser-thc/thc-hydra)
    """

    def get_scan_types(self):
        return ["Hydra Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Hydra Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Hydra Scan can be imported in JSON format."

    def get_findings(self, json_output, test):
        report = self.__parse_json(json_output)

        metadata = HydraScanMetadata(report["generator"])
        findings = self.__extract_findings(report["results"], metadata, test)

        return findings

    def __extract_findings(self, raw_findings, metadata: HydraScanMetadata, test):
        findings = []

        for raw_finding in raw_findings:
            finding = self.__extract_finding(raw_finding, metadata, test)
            findings.append(finding)

        return findings

    def __extract_finding(self, raw_finding, metadata: HydraScanMetadata, test) -> Finding:
        host = raw_finding['host']
        port = raw_finding['port']
        username = raw_finding['login']
        password = raw_finding['password']
        
        finding = Finding(
            test=test,
            title="Weak username / password combination found for " + host,
            date=parse_datetime(metadata.date),
            severity="High",
            description=host + " on port " + str(port) + " is allowing logins with easy to guess username " + username + " and password " + password,
            static_finding=metadata.static_finding,
            dynamic_finding=metadata.dynamic_finding,
            service=metadata.service_type,
        )

        return finding

    @staticmethod
    def __parse_json(json_output):
        report = json.load(json_output)

        if 'generator' not in report or 'results' not in report:
            raise ValueError(" Unexpected JSON format provided. That doesn't look like a Hydra scan!")

        return report

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