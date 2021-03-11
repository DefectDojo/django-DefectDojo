import json
import hashlib
import re

from dojo.models import Finding, Endpoint



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

    def process_endpoints(self, finding, url, url_protocol, url_path):

        try:
            dupe_endpoint = Endpoint.objects.get(protocol=url_protocol,
                                                 host=url,
                                                 query="",
                                                 fragment="",
                                                 path=url_path
                                                 )
        except Endpoint.DoesNotExist:
            dupe_endpoint = None

        if not dupe_endpoint:
            endpoint = Endpoint(protocol=url_protocol,
                                host=url,
                                query="",
                                fragment="",
                                path=url_path
                                )
        else:
            endpoint = dupe_endpoint

        if not dupe_endpoint:
            endpoints = [endpoint]
        else:
            endpoints = [endpoint, dupe_endpoint]

        finding.unsaved_endpoints = finding.unsaved_endpoints + endpoints


    def get_findings(self, filename, test):
        # table to match HTTP error code and severity
        SEVERITY = {
            200: "High",
            500: "Low",
            401: "Medium",
            407: "Medium",
            403: "Medium"
        }
        url_regexp = "(?P<url_protocol>(https|http))?:\/\/(?P<url>.*)(?P<url_port>[0-9]*)?\/?(?P<url_path>.*)$"

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
                    finding = Finding(title='Found ' + m.group('url_protocol') + '://' + url + url_path,
                                              test=test,
                                              severity=severity,
                                              numerical_severity=Finding.get_numerical_severity(severity),
                                              description="The URL " + m.group('url_protocol') + '://' +
                                                          url + url_path +
                                                          " must not be exposed\n Please review your configuration\n",
                                              payload=payload,
                                              mitigation='N/A',
                                              url=str(url + url_path),
                                              static_finding=False,
                                              dynamic_finding=True,
                                              cwe=200
                                              )
                    self.process_endpoints(finding, url, m.group("url_protocol"), url_path)
                    dupes[dupe_key] = finding
        return list(dupes.values())
