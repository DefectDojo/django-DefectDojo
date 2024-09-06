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

    def get_findings(self, filename, test):
        data = json.load(filename)
        assessment_name = test.title
        if assessment_name.startswith("[RETEST]"):
            true_name = assessment_name.replace("[RETEST] ", "")
            findings = PTARTRetestParser().get_findings_for(true_name, data)
        else:
            findings = PTARTAssessmentParser().get_findings_for(assessment_name, data)
        return findings

    def get_tests(self, scan_type, filename):
        data = json.load(filename)
        tests = PTARTAssessmentParser().get_test_data(data)
        tests.extend(PTARTRetestParser().get_test_data(data))
        return tests

    def requires_file(self, scan_type):
        return True