import json
import hashlib
import hyperlink

from dojo.models import Finding, Endpoint


class WFuzzParser(object):
    """
    A class that can be used to parse the WFuzz JSON report files
    """

    # table to match HTTP error code and severity
    SEVERITY = {
        "200": "High",
        "500": "Low",
        "401": "Medium",
        "407": "Medium",
        "403": "Medium",
    }

    def get_scan_types(self):
        return ["WFuzz JSON report"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import WFuzz findings in JSON format."

    def get_findings(self, filename, test):

        data = json.load(filename)

        dupes = {}
        for item in data:
            url = hyperlink.parse(item["url"])
            payload = item["payload"]
            return_code = str(item["code"])
            severity = self.SEVERITY[return_code]
            description = f"The URL {url.to_text()} must not be exposed\n Please review your configuration\n"

            dupe_key = hashlib.sha256(
                (url.to_text() + return_code).encode("utf-8")
            ).hexdigest()

            if dupe_key in dupes:
                finding = dupes[dupe_key]
                finding.nb_occurences += 1
            else:
                finding = Finding(
                    title=f"Found {url.to_text()}",
                    test=test,
                    severity=severity,
                    description=description,
                    mitigation="N/A",
                    static_finding=False,
                    dynamic_finding=True,
                    cwe=200,
                    nb_occurences=1,
                )
                finding.unsaved_endpoints = [
                    Endpoint(
                        path="/".join(url.path),
                        host=url.host,
                        protocol=url.scheme,
                        port=url.port,
                    )
                ]
                finding.unsaved_req_resp = [
                    {"req": item["payload"], "resp": str(item["code"])}
                ]
                dupes[dupe_key] = finding
        return list(dupes.values())
