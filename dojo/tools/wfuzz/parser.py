import json
import hashlib

from dojo.models import Finding


class WFuzzParser(object):
    """
        A class that can be used to parse the WFuzz JSON report files
    """

    def get_scan_types(self):
        return ["WFuzz"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_label_for_scan_types(self, scan_type):
        return "WFuzz JSON report"

    def get_description_for_scan_types(self, scan_type):
        return "Import WFuzz findings in JSON format."

    def get_findings(self, filename, test):

        # table to match HTTP error code and severity
        SEVERITY = {
            200: "High",
            500: "Low",
            401: "Medium",
            407: "Medium",
            403: "Medium"
        }

        # Exit if no file provided
        if filename is None:
            return

        dupes = {}
        issues = json.load(filename)

        if issues is not None:
            for item in issues:
                url = item['url']
                payload = item['payload']
                return_code = int(item['code'])
                severity = SEVERITY[return_code]
                dupe_key = hashlib.md5(str(url + str(return_code)).encode("utf-8")).hexdigest()

                if dupe_key not in dupes:
                    dupes[dupe_key] = Finding(title='Found ' + url + ' URL',
                                              test=test,
                                              severity=severity,
                                              numerical_severity=Finding.get_numerical_severity(severity),
                                              description=payload,
                                              mitigation='N/A',
                                              file_path='N/A',
                                              url=url,
                                              static_finding=False,
                                              dynamic_finding=True
                                              )

        return list(dupes.values())
