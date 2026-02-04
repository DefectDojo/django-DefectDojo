import json

from dojo.tools.wazuh.v4_7 import WazuhV4_7
from dojo.tools.wazuh.v4_8 import WazuhV4_8


class WazuhParser:

    """
    The vulnerabilities with condition "Package unfixed" are skipped because there is no fix out yet.
    https://github.com/wazuh/wazuh/issues/14560
    """

    def get_scan_types(self):
        return ["Wazuh"]

    def get_label_for_scan_types(self, scan_type):
        return "Wazuh"

    def get_description_for_scan_types(self, scan_type):
        return "Wazuh"

    def get_findings(self, file, test):
        data = json.load(file)
        if not data:
            return []

        # Loop through each element in the list
        if data.get("data"):
            return WazuhV4_7().parse_findings(test, data)
        if data.get("hits"):
            return WazuhV4_8().parse_findings(test, data)
        return []
