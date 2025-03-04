import json

from dojo.models import Finding


class AquaParser:

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Aqua Parser.

        Fields:
        - title: Made by combining cve, resource_name, and resource_version.
        - severity: Severity converted from Aqua format into Defect Dojo format.
        - severity_justification: Set to justification returned by Aqua scanner.
        - cvssv3: Defined based on the output of the Aqua Scanner.
        - description: Set to description returned from Aqua Scanner. If no description is present set to "no description".
        - mitigation: Set to fix_version returned from Aqua Scanner.
        - references: Set to url returned from Aqua Scanner.
        - component_name: Set to name returned from Aqua Scanner.
        - component_version: Set to version returned from Aqua Scanner.
        - impact: Set to same value as severity.
        - epss_score: Set to epss_score returned from scanner if it exists.
        - epss_percentile: Set to epss_percentile returned from scanner if it exists.
        """
        return [
            "title",
            "severity",
            "severity_justification",
            "cvssv3",
            "description",
            "mitigation",
            "references",
            "component_name",
            "component_version",
            "impact",
            "epss_score",
            "epss_percentile",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Aqua Parser.

        Fields:
        - severity: Severity converted from Aqua format into Defect Dojo format.
        - component_name: Set to name returned from Aqua Scanner.
        - component_version: Set to version returned from Aqua Scanner.

        #NOTE: vulnerability_ids is not provided by parser
        """
        return [
            "severity",
            "component_name",
            "component_version",
        ]

    # Jino This get_fields was written for the Aque Parser v2 (based off of "get_iten_v2")
    # What do we do with the seperate versions of this parser?
    # def get_fields(self) -> list[str]:
    #     """
    #     Return the list of fields used in the Aqua Parser V2
    #
    #     Fields:
    #     - title: Created by combining the finding's cve and file_path
    #     - description: Text describing finding
    #     - url: Url associated with the finding
    #     - severity: Severity rating converted from Aqua's integer format into DefectDojo's format.
    #       #Jino: On line 106 it calls severity_of instead of aqua_severity_of. get_item v1 uses aqua_severity_of#
    #     - impact: Impact rating of finding. Same as the finding severity.
    #     - mitigation: If solution is true, mitigation equals true. If fix_version is true, mitigation equals 'Upgrade to True'.If neither are true mitigation equals 'No known mitigation'.
    #     """
    #     return [
    #         "title",
    #         "description",
    #         "url",
    #         "severity",
    #         "impact",
    #         "mitigation",
    #     ]
    # Dedupe for v2 based on default dedupe values
    # def get_dedupe_fields(self) -> list[str]:
    #     """
    #     Return the list of fields used for deduplication in the Aqua Parser V2.
    #
    #     Fields:
    #     - title: Created by combining the finding's cve and file_path
    #     - description: Text describing finding
    #     """
    #     #NOTE: vulnerability_ids is not provided by parser
    #     return [
    #         "title",
    #         "description",
    #     ]
    def get_scan_types(self):
        return ["Aqua Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Aqua Scan"

    def get_description_for_scan_types(self, scan_type):
        return ""

    def get_findings(self, json_output, test):
        tree = json.load(json_output)
        return self.get_items(tree, test)

    def get_items(self, tree, test):
        self.items = {}
        if isinstance(tree, list):  # Aqua Scan Report coming from Azure Devops jobs.
            vulnerabilitytree = tree[0]["results"]["resources"] if tree else []
            self.vulnerability_tree(vulnerabilitytree, test)
        elif "resources" in tree:  # Aqua Scan Report not from Azure Devops jobs.
            vulnerabilitytree = tree["resources"]
            self.vulnerability_tree(vulnerabilitytree, test)
        elif "cves" in tree:       # Aqua Scan Report not from Azure Devops jobs.
            for cve in tree["cves"]:
                unique_key = cve.get("file") + cve.get("name")
                self.items[unique_key] = get_item_v2(cve, test)
        return list(self.items.values())

    def vulnerability_tree(self, vulnerabilitytree, test):
        for node in vulnerabilitytree:
            resource = node.get("resource")
            vulnerabilities = node.get("vulnerabilities", [])
            sensitive_items = resource.get("sensitive_items", [])
            if vulnerabilities is None:
                vulnerabilities = []
            for vuln in vulnerabilities:
                item = get_item(resource, vuln, test)
                unique_key = resource.get("cpe") + vuln.get("name", "None") + resource.get("path", "None")
                self.items[unique_key] = item
            if sensitive_items is None:
                sensitive_items = []
            for sensitive_item in sensitive_items:
                item = get_item_sensitive_data(resource, sensitive_item, test)
                unique_key = resource.get("cpe") + resource.get("path", "None") + str(sensitive_item)
                self.items[unique_key] = item


def get_item(resource, vuln, test):
    resource_name = resource.get("name", resource.get("path"))
    resource_version = resource.get("version", "No version")
    vulnerability_id = vuln.get("name", "No CVE")
    fix_version = vuln.get("fix_version", "None")
    description = vuln.get("description", "No description.") + "\n"
    if resource.get("path"):
        description += "**Path:** " + resource.get("path") + "\n"
    cvssv3 = None

    url = ""
    if "nvd_url" in vuln:
        url += "\n{}".format(vuln.get("nvd_url"))
    if "vendor_url" in vuln:
        url += "\n{}".format(vuln.get("vendor_url"))

    # Take in order of preference (most prio at the bottom of ifs), and put
    # everything in severity justification anyways.
    score = 0
    severity_justification = ""
    used_for_classification = ""
    if "aqua_severity" in vuln:
        score = vuln.get("aqua_severity")
        severity = aqua_severity_of(score)
        used_for_classification = (
            f"Aqua security score ({score}) used for classification.\n"
        )
        severity_justification = vuln.get("aqua_severity_classification")
        if "nvd_score_v3" in vuln:
            cvssv3 = vuln.get("nvd_vectors_v3")
    else:
        if "aqua_score" in vuln:
            score = vuln.get("aqua_score")
            used_for_classification = (
                f"Aqua score ({score}) used for classification.\n"
            )
        elif "vendor_score" in vuln:
            score = vuln.get("vendor_score")
            used_for_classification = (
                f"Vendor score ({score}) used for classification.\n"
            )
        elif "nvd_score_v3" in vuln:
            score = vuln.get("nvd_score_v3")
            used_for_classification = (
                f"NVD score v3 ({score}) used for classification.\n"
            )
            severity_justification += "\nNVD v3 vectors: {}".format(
                vuln.get("nvd_vectors_v3"),
            )
            # Add the CVSS3 to Finding
            cvssv3 = vuln.get("nvd_vectors_v3")
        elif "nvd_score" in vuln:
            score = vuln.get("nvd_score")
            used_for_classification = (
                f"NVD score v2 ({score}) used for classification.\n"
            )
            severity_justification += "\nNVD v2 vectors: {}".format(
                vuln.get("nvd_vectors"),
            )
        severity = severity_of(score)
        severity_justification += f"\n{used_for_classification}"

    finding = Finding(
        title=vulnerability_id
        + " - "
        + resource_name
        + " ("
        + resource_version
        + ") ",
        test=test,
        severity=severity,
        severity_justification=severity_justification,
        cwe=0,
        cvssv3=cvssv3,
        description=description.strip(),
        mitigation=fix_version,
        references=url,
        component_name=resource.get("name"),
        component_version=resource.get("version"),
        impact=severity,
    )
    if vulnerability_id != "No CVE":
        finding.unsaved_vulnerability_ids = [vulnerability_id]
    if vuln.get("epss_score"):
        finding.epss_score = vuln.get("epss_score")
    if vuln.get("epss_percentile"):
        finding.epss_percentile = vuln.get("epss_percentile")
    return finding


def get_item_v2(item, test):
    vulnerability_id = item["name"]
    file_path = item["file"]
    url = item.get("url")
    severity = severity_of(float(item["score"]))
    description = item.get("description")
    solution = item.get("solution")
    fix_version = item.get("fix_version")
    if solution:
        mitigation = solution
    elif fix_version:
        mitigation = "Upgrade to " + str(fix_version)
    else:
        mitigation = "No known mitigation"

    finding = Finding(
        title=str(vulnerability_id) + ": " + str(file_path),
        description=description,
        url=url,
        cwe=0,
        test=test,
        severity=severity,
        impact=severity,
        mitigation=mitigation,
    )
    finding.unsaved_vulnerability_ids = [vulnerability_id]

    return finding


def get_item_sensitive_data(resource, sensitive_item, test):
    resource_name = resource.get("name", "None")
    resource_path = resource.get("path", "None")
    vulnerability_id = resource_name
    description = "**Senstive Item:** " + sensitive_item + "\n"
    description += "**Layer:** " + resource.get("layer", "None") + "\n"
    description += "**Layer_Digest:** " + resource.get("layer_digest", "None") + "\n"
    description += "**Path:** " + resource.get("path", "None") + "\n"
    finding = Finding(
        title=vulnerability_id
        + " - "
        + resource_name
        + " ("
        + resource_path
        + ") ",
        test=test,
        severity="Info",
        description=description.strip(),
        component_name=resource.get("name"),
    )
    if vulnerability_id != "No CVE":
        finding.unsaved_vulnerability_ids = [vulnerability_id]

    return finding


def aqua_severity_of(score):
    if score == "high":
        return "High"
    if score == "medium":
        return "Medium"
    if score == "low":
        return "Low"
    if score == "negligible":
        return "Info"
    return "Critical"


def severity_of(score):
    if score == 0:
        return "Info"
    if score < 4:
        return "Low"
    if 4.0 < score < 7.0:
        return "Medium"
    if 7.0 < score < 9.0:
        return "High"
    return "Critical"
