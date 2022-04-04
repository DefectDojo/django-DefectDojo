import json
from datetime import date
import logging

from dojo.models import Finding, Endpoint
from django.utils.dateparse import parse_datetime

logger = logging.getLogger(__name__)


class HydraScanMetadata:
    def __init__(self, generator):
        self.date = generator.get('built', )
        self.command = generator.get('commandline')
        self.schema_version = generator.get('jsonoutputversion')
        self.service_type = generator.get('service')
        self.tool_version = generator.get('version')
        self.server = generator.get('server')


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
            try:
                finding = self.__extract_finding(raw_finding, metadata, test)
                findings.append(finding)
            except ValueError:
                logger.warning('Error when digesting a finding from hydra! Please revise supplied report, vital information was missing (e.g. host)!')

        return findings

    def __extract_finding(self, raw_finding, metadata: HydraScanMetadata, test) -> Finding:
        host = raw_finding.get('host')
        port = raw_finding.get('port')
        username = raw_finding.get('login')
        password = raw_finding.get('password')

        if (host is None) or (port is None) or (username is None) or (password is None):
            raise ValueError("Vital information is missing for this finding! Skipping this finding!")

        finding = Finding(
            test=test,
            title="Weak username / password combination found for " + host,
            date=parse_datetime(metadata.date) if metadata.date else date.today(),
            severity="High",
            description=host + " on port " + str(port) + " is allowing logins with easy to guess username " + username + " and password " + password,
            static_finding=False,
            dynamic_finding=True,
            service=metadata.service_type,
        )
        finding.unsaved_endpoints = [Endpoint(host=host, port=port)]

        return finding

    @staticmethod
    def __parse_json(json_output):
        report = json.load(json_output)

        if 'generator' not in report or 'results' not in report:
            raise ValueError("Unexpected JSON format provided. That doesn't look like a Hydra scan!")

        return report
