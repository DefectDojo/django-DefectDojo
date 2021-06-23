import json
import hashlib
from datetime import datetime
from dojo.models import Finding, Endpoint


class GitlabDastParser(object):
    """
    Import GitLab DAST Report in JSON format
    """

    def get_scan_types(self):
        return ["GitLab DAST Report"]

    def get_label_for_scan_types(self, scan_type):
        return "GitLab DAST Report"

    def get_description_for_scan_types(self, scan_type):
        return "GitLab DAST Report in JSON format (option --json)."

    def get_findings(self, file, test):
        if file is None:
            return None

        # tree = self.parse_json(file)
        # if tree:
        return self.get_items(json.load(file), test)

    def get_items(self, tree, test):
        items = {}

        # iterating through each vulnerability
        for node in tree["vulnerabilities"]:
            item = get_item(node, test)

            item_key = hashlib.sha256(
                "|".join([item.severity, item.title, item.description]).encode()
            ).hexdigest()

            if item_key in items:
                items[item_key].unsaved_endpoints.extend(item.unsaved_endpoints)
                items[item_key].nb_occurences += 1
            else:
                items[item_key] = item

        return list(items.values())

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


# iterating through properties of each vulnerability
def get_item(vuln, test):
    if vuln["category"] != "dast":
        return None

    # scanner_confidence
    scanner_confidence = get_confidence_numeric(vuln["confidence"])

    # description
    description = f"Scanner: {vuln['scanner']['name']}\n"
    if "message" in vuln:
        description += f"{vuln['message']}\n"
    elif "description" in vuln:
        description += f"{vuln['description']}\n"

    finding = Finding(
        test=test,  # Test
        nb_occurences=1,  # int
        scanner_confidence=scanner_confidence,  # int
        description=description,  # str
        static_finding=False,
        dynamic_finding=True,
    )

    # date
    if "discovered_at" in vuln:
        finding.date = datetime.strptime(vuln["discovered_at"], "%Y-%m-%dT%H:%M:%S.%f")

    # id
    if "id" in vuln:
        finding.unique_id_from_tool = vuln["id"]

    # title
    if "name" in vuln:
        finding.title = vuln["name"]
    # fallback to using id as a title
    else:
        finding.title = finding.unique_id_from_tool

    # cwe
    for identifier in vuln["identifiers"]:
        if "cwe" == identifier["type"].lower():
            finding.cwe = int(identifier["value"])
            break

    # references
    if vuln["links"]:
        ref = ""
        for link in vuln["links"]:
            ref += f"{link['url']}\n"
        ref = ref[:-1]
        finding.references = ref

    # severity
    if "severity" in vuln:
        finding.severity = vuln["severity"]

    # endpoint
    location = vuln.get("location", {})
    if "hostname" in location and "path" in location:
        url_str = f"{location['hostname']}{location['path']}"
        finding.unsaved_endpoints = [Endpoint.from_uri(url_str)]

    # mitigation
    if "solution" in vuln:
        finding.mitigation = vuln["solution"]

    return finding


def get_confidence_numeric(confidence):
    switcher = {
        "Confirmed": 1,  # Certain
        "High": 3,  # Firm
        "Medium": 4,  # Firm
        "Low": 6,  # Tentative
        "Experimental": 7,  # Tentative
        "Unknown": 8,  # Tentative
        "Ignore": 10,  # Tentative
    }
    return switcher.get(confidence, None)
