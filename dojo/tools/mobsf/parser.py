
import json

from dojo.tools.mobsf.api_report_json import MobSFapireport
from dojo.tools.mobsf.report import MobSFjsonreport


class MobSFParser:

    def get_scan_types(self):
        return ["MobSF Scan", "Mobsfscan Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "MobSF Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON report from mobsfscan report file or from api/v1/report_json"

    def get_findings(self, filename, test):
        tree = filename.read()
        try:
            data = json.loads(str(tree, "utf-8"))
        except:
            data = json.loads(tree)
        if isinstance(data, list) or data.get("results") is None:
            return MobSFapireport().get_findings(data, test)
        if len(data.get("results")) == 0:
            return []
        return MobSFjsonreport().get_findings(data, test)
