import json

from dojo.tools.generic.csv_parser import GenericCSVParser
from dojo.tools.generic.json_parser import GenericJSONParser
from dojo.tools.parser_test import ParserTest
import logging

logger = logging.getLogger(__name__)


class GenericParser:
    ID = "Generic Findings Import"

    def get_scan_types(self):
        return [self.ID]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import Generic findings in CSV or JSON format."

    def get_findings(self, filename, test, **kwargs):
        if filename.name.lower().endswith(".csv"):
            return GenericCSVParser()._get_findings_csv(filename, **kwargs)
        elif filename.name.lower().endswith(".json"):
            data = json.load(filename)
            test_internal = GenericJSONParser()._get_test_json(data, **kwargs)
            return test_internal.findings
        else:  # default to CSV like before
            return GenericCSVParser()._get_findings_csv(filename, **kwargs)

    def get_tests(self, scan_type, filename, **kwargs):

        # if the file is a CSV just use the old function
        if filename.name.lower().endswith(".csv"):
            test = ParserTest(name=self.ID, type=self.ID, version=None)
            test.findings = GenericCSVParser()._get_findings_csv(filename, **kwargs)
            return [test]
        # we manage it like a JSON file (default)
        data = json.load(filename)
        return [GenericJSONParser()._get_test_json(data, **kwargs)]

    def requires_file(self, scan_type):
        return True
