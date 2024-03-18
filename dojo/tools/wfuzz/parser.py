import json
import hashlib
import hyperlink

from dojo.models import Finding, Endpoint


class WFuzzParser(object):
    """
    A class that can be used to parse the WFuzz JSON report files
    """

    # match HTTP error code and severity
    def severity_mapper(self, input):
        if 200 <= int(input) <= 299:
            return "High"
        elif 300 <= int(input) <= 399:
            return "Low"
        elif 400 <= int(input) <= 499:
            return "Medium"
        elif 500 <= int(input):
            return "Low"

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
            return_code = item.get("code", None)
            if return_code is None:
                severity = "Low"
            else:
                severity = self.severity_mapper(input=return_code)
            description = f"The URL {url.to_text()} must not be exposed\n Please review your configuration\n"
            dupe_key = hashlib.sha256(
                (url.to_text() + str(return_code)).encode("utf-8")
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
                    {"req": item["payload"], "resp": str(return_code)}
                ]
                dupes[dupe_key] = finding
        return list(dupes.values())
