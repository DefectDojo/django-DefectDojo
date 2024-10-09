import json

import dojo.tools.ptart.ptart_parser_tools as ptart_tools
from dojo.models import Test
from dojo.tools.parser_test import ParserTest
from dojo.tools.ptart.assessment_parser import PTARTAssessmentParser
from dojo.tools.ptart.retest_parser import PTARTRetestParser


class PTARTParser(object):
    """
    Imports JSON reports from the PTART (https://github.com/certmichelin/PTART) reporting tool
    """

    def get_scan_types(self):
        return ["PTART Report"]

    def get_label_for_scan_types(self, scan_type):
        return "PTART Report"

    def get_description_for_scan_types(self, scan_type):
        return "Import a PTART report file in JSON format."

    def get_tests(self, scan_type, scan):
        data = json.load(scan)

        test = ParserTest(
            name="Pen Test Report",
            type="Pen Test",
            version="",
        )

        if "name" in data:
            test.name = data["name"] + " Report"
            test.type = data["name"] + " Report"

        description = ""
        if "executive_summary" in data:
            description += data["executive_summary"] + '\n\n'

        if "engagement_overview" in data:
            description += data["engagement_overview"] + '\n\n'

        if "conclusion" in data:
            description += data["conclusion"]

        if description:
            test.description = description

        if "start_date" in data:
            test.target_start = ptart_tools.parse_date(data["start_date"], "%Y-%m-%d")

        if "end_date" in data:
            test.target_end = ptart_tools.parse_date(data["end_date"], "%Y-%m-%d")

        findings = self.get_items(data)
        test.findings = findings
        return [test]

    def get_findings(self, file, test):
        data = json.load(file)
        return self.get_items(data)

    def get_items(self, data):
        findings = PTARTAssessmentParser().get_test_data(data)
        findings.extend(PTARTRetestParser().get_test_data(data))
        return findings

    def requires_file(self, scan_type):
        return True
