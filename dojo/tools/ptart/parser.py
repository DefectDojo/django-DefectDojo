import hashlib
import json
from urllib.parse import urlparse
from dojo.models import Endpoint, Finding


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
        project = json.load(file)

        if project is not None:


    def convert_severity(self, num_severity):
        """Convert severity value"""
        if num_severity >= -10:
            return "Low"
        elif -11 >= num_severity > -26:
            return "Medium"
        elif num_severity <= -26:
            return "High"
        else:
            return "Info"
