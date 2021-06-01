import json
from datetime import datetime
from urllib.parse import urlparse

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

    # turning a json file to string
    def parse_json(self, file):
        data = file.read()
        try:
            tree = json.loads(str(data, 'utf-8'))
        except:
            tree = json.loads(data)

        return tree

    def get_items(self, tree, test):
        items = {}

        # iterating through each vulnerability
        for node in tree['vulnerabilities']:
            item = get_item(node, test)
            if item:
                items[item.unique_id_from_tool] = item

        return list(items.values())

    def get_findings(self, file, test):
        if file is None:
            return None

        tree = self.parse_json(file)
        if tree:
            return self.get_items(tree, test)

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

    # id
    if "id" in vuln:
        unique_id_from_tool = vuln["id"]
    else:  # deprecated
        unique_id_from_tool = vuln["cve"]

    # title
    if "name" in vuln:
        title = vuln["name"]
    # fallback to using id as a title
    else:
        title = unique_id_from_tool

    # description
    description = f"Scanner: {vuln['scanner']['name']}\n"
    if "message" in vuln:
        description += f"{vuln['message']}\n"
    elif "description" in vuln:
        description += f"{vuln['description']}\n"

    # date
    if "discovered_at" in vuln:
        temp = vuln["discovered_at"][:-4]
        date = datetime.strptime(temp, "%Y-%m-%dT%H:%M:%S")
    else:
        date = None

    # endpoint
    location = vuln["location"]
    if "hostname" in location and "path" in location:
        url = f"{location['hostname']}{location['path']}"

        o = urlparse(url)
        protocol = o.scheme

        port = 80
        if protocol == "https":
            port = 443
        if o.port is not None:
            port = o.port

        host = o.netloc
        query = o.query
        fragment = o.fragment
        path = o.path

        endpoint = Endpoint(
            protocol=protocol,
            host=host,
            port=port,
            query=query,
            fragment=fragment,
            path=path
        )
    else:
        endpoint = None

    # TODO: found_by

    # severity
    severity = vuln["severity"]
    if severity is None:
        severity = "Unknown"

    # numerical_severity
    numerical_severity = Finding.get_numerical_severity(severity)

    if "solution" in vuln:
        mitigation = vuln["solution"]

    cve = vuln["cve"]

    references = ""
    for ref in vuln["identifiers"]:
        if ref["type"].lower() == "cwe":
            cwe = int(ref["value"])
        else:
            references += f"Identifier type: {ref['type']}\n"
            references += f"Name: {ref['name']}\n"
            references += f"Value: {ref['value']}\n"
            if "url" in ref:
                references += f"URL: {ref['url']}\n"
            references += '\n'

    finding = Finding(
        test=test,  # Test
        unique_id_from_tool=unique_id_from_tool,  # str
        scanner_confidence=scanner_confidence,  # int
        title=title,  # str
        description=description,  # str
        date=date,  # datetime object
        references=references,  # str (identifiers)
        severity=severity,  # str
        numerical_severity=numerical_severity,  # str
        mitigation=mitigation,  # str (solution)
        cwe=cwe,  # int
        cve=cve  # str
    )

    finding.unsaved_endpoints = [endpoint]

    return finding


def get_confidence_numeric(confidence):
    switcher = {
        'Confirmed': 1,    # Certain
        'High': 3,         # Firm
        'Medium': 4,       # Firm
        'Low': 6,          # Tentative
        'Experimental': 7, # Tentative
        'Unknown': 8,      # Tentative
        'Ignore': 10,      # Tentative
    }
    return switcher.get(confidence, None)
