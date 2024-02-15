import json
from dojo.models import Finding, Endpoint


class HumbleParser(object):
    """Humble (https://github.com/rfc-st/humble)"""

    def get_scan_types(self):
        return ["Humble Json Importer"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "JSON output of Humble scan."

    def get_findings(self, filename, test):
        items = []
        try:
            data = json.load(filename)
        except ValueError:
            data = {}
        if data != {}:
            url = data['[0. Info]']['URL']
            for content in data['[1. Missing HTTP Security Headers]']:
                if content != "Nothing to report, all seems OK!":
                    finding = Finding(title="Missing header: " + str(content),
                        description="This security Header is missing: " + content,
                        severity="Medium",
                        static_finding=False,
                        dynamic_finding=True)
                    items.append(finding)
                    finding.unsaved_endpoints = [Endpoint.from_uri(url)]
            for content in data['[2. Fingerprint HTTP Response Headers]']:
                if content != "Nothing to report, all seems OK!":
                    finding = Finding(title="Available fingerprint:" + str(content),
                        description="This fingerprint HTTP Response Header is available. Please remove it: " + content,
                        severity="Medium",
                        static_finding=False,
                        dynamic_finding=True)
                    items.append(finding)
                    finding.unsaved_endpoints = [Endpoint.from_uri(url)]
            for content in data['[3. Deprecated HTTP Response Headers/Protocols and Insecure Values]']:
                if content != "Nothing to report, all seems OK!":
                    finding = Finding(title="Deprecated header: " + str(content),
                        description="This deprecated HTTP Response Header is available. Please remove it: " + content,
                        severity="Medium",
                        static_finding=False,
                        dynamic_finding=True)
                    items.append(finding)
                    finding.unsaved_endpoints = [Endpoint.from_uri(url)]
            for content in data['[4. Empty HTTP Response Headers Values]']:
                if content != "Nothing to report, all seems OK!":
                    finding = Finding(title="Empty HTTP response header: " + str(content),
                        description="This empty HTTP Response Header value is available. Please remove it: " + content,
                        severity="Medium",
                        static_finding=False,
                        dynamic_finding=True)
                    items.append(finding)
                    finding.unsaved_endpoints = [Endpoint.from_uri(url)]
        return items
