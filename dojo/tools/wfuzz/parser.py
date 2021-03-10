import json
import hashlib
import re

from dojo.models import Finding


class WFuzzParser(object):
    """
        A class that can be used to parse the WFuzz JSON report files
    """

    def get_scan_types(self):
        return ["WFuzz JSON report"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

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
        url_regexp = "(?P<url>https?:\/\/.*)(?P<url_port>[0-9]*)?\/?(?P<url_path>.*)$"

        # Exit if no file provided
        if filename is None:
            return

        dupes = {}
        issues = json.load(filename)

        if issues is not None:
            for item in issues:
                m = re.match(url_regexp, item['url'])
                url = m.group("url") + m.group('url_port')
                url_path = m.group("url_path")

                payload = item['payload']
                return_code = int(item['code'])
                severity = SEVERITY[return_code]
                dupe_key = hashlib.md5(str(url + str(return_code) + url_path).encode("utf-8")).hexdigest()

                if dupe_key not in dupes:
                    dupes[dupe_key] = Finding(title='Found ' + url + url_path,
                                              test=test,
                                              severity=severity,
                                              numerical_severity=Finding.get_numerical_severity(severity),
                                              description="The URL " + url + url_path + " must not be exposed\n Please review your configuration\n",
                                              payload=payload,
                                              mitigation='N/A',
                                              url=str(url + url_path),
                                              static_finding=False,
                                              dynamic_finding=True,
                                              cwe=200
                                              )

        return list(dupes.values())
