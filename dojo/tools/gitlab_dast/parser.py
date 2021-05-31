import json
from urllib.parse import urlparse

from dojo.models import Finding, Endpoint

class GitlabDastParser(object):
    """
    Import GitLab DAST Report in JSON N format
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
    """ Need
    - title (done)
    - test (done -- given)
    - description (done)
    - severity (done)
    
    - static_finding=False
    - dynamic_finding=True
    """

    if vuln["category"] != "dast":
        return None
    
    if "id" in vuln:
        unique_id_from_tool = vuln["id"]
    # deprecated
    else:
        unique_id_from_tool = vuln["cve"]

    if "name" in vuln:
        title = vuln["name"]
    # fallback to using id as a title
    else:
        title = unique_id_from_tool

    description = f"Scanner: {vuln['scanner']['name']}\n"
    if "message" in vuln:
        description += f"{vuln['message']}\n"
    elif "description" in vuln:
        description += f"{vuln['description']}\n"

    severity = vuln["severity"]
    if severity == None:
        severity = "Unknown"

    numerical_severity = Finding.get_numerical_severity(severity)
    
    scanner_confidence = get_confidence_numeric(vuln["confidence"])

    location = vuln["location"]
    if "hostname" in location and "path" in location:
        url = f"{location['hostname']}{location['path']}"

        o = urlparse(url)
        protocol = o.scheme

        port = 80
        if protocol == 'https':
            port = 443
        if o.port is not None:
            port = o.port

        host = o.netloc
        query = o.query
        fragment = o.fragment
        path = o.path

        endpoints = Endpoint(protocol=protocol,
                                host=host,
                                port=port,
                                query=query,
                                fragment=fragment,
                                path=path)
    else:
        endpoints = None

    if "solution" in vuln:
        mitigation = vuln["solution"]

    cve = vuln["cve"]
    
    references = ""
    for ref in vuln["identifiers"]:
        if ref["type"].lower() == "cwe":
            cwe = ref["value"]
        else:
            references += f"Identifier type: {ref['type']}\n"
            references += f"Name: {ref['name']}\n"
            references += f"Value: {ref['value']}\n"
            if "url" in ref:
                references += f"URL: {ref['url']}\n"
            references += '\n'

    findings = Finding(
        title = title,
        unique_id_from_tool = unique_id_from_tool,
        test = test,
        description = description,
        severity = severity,
        scanner_confidence = scanner_confidence,
        numerical_severity = numerical_severity,
        mitigation = mitigation,
        references = references,
        endpoints = endpoints,
        cwe = cwe,
        cve = cve,

        static_finding = True,
        dynamic_finding = False
    )

    return findings

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