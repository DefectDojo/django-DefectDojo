import json

from dojo.tools.ptart.retest_parser import PTARTRetestParser
from dojo.tools.ptart.assessment_parser import PTARTAssessmentParser

class PTARTParser(object):
    """
    Imports JSON reports from the PTART (https://github.com/certmichelin/PTART) reporting tool
    """

    def get_scan_types(self):
        return ["PTART Report"]

    def get_label_for_scan_types(self, scan_type):
        return "PTART Report"

    def get_description_for_scan_types(self, scan_type):
        return "PTART report file can be imported in JSON format."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = PTARTAssessmentParser().get_test_data(data)
        findings.extend(PTARTRetestParser().get_test_data(data))
        return findings

    def requires_file(self, scan_type):
        return True