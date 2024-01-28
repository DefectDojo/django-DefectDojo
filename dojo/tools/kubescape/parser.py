import json
from dojo.models import Endpoint, Finding


class KubescapeParser(object):
    def get_scan_types(self):
        return ["Kubescape JSON Importer"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import result of Kubescape JSON output."

    def get_findings(self, filename, test):
        findings = []
        try:
            data = json.load(filename)
        except ValueError:
            data = {}
        i=0
        for resource in data["resources"]:
            resourceid = resource["resourceID"]
            results = ([each for each in data["results"] if each.get('resourceID') == resourceid])
            """TODO, PARSE THE RIGHT VALUES INTO THE FINDING"""
            i+=1
            find = Finding(title="title"+str(i),
            test=test,
            description="message",
            severity="High",
            static_finding=False)
            findings.append(find)
        return findings
