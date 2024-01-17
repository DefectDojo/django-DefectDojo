import json
import logging
from dojo.models import Finding
logger = logging.getLogger(__name__)


class ClairParser(object):
    def get_scan_types(self):
        return ["Clair Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON reports of Docker image vulnerabilities from clair or clair klar client."

    def get_findings(self, json_output, test):
        tree = self.parse_json(json_output)
        if tree:
            if self.scanner == "clair":
                return self.get_items_clair(tree, test)
            elif self.scanner == "clairklar":
                items = list()
                clair_severities = [
                    "Unknown",
                    "Negligible",
                    "Low",
                    "Medium",
                    "High",
                    "Critical",
                    "Defcon1",
                ]
                for clair_severity in clair_severities:
                    items.extend(
                        self.set_items_for_severity(tree, test, clair_severity)
                    )
                return items
        else:
            return list()

    def parse_json(self, json_output):
        try:
            data = json_output.read()
            try:
                tree = json.loads(str(data, "utf-8"))
            except BaseException:
                tree = json.loads(data)
            if tree.get('image'):
                self.scanner = "clair"
                subtree = tree.get("vulnerabilities")
            elif tree.get('LayerCount'):
                self.scanner = "clairklar"
                subtree = tree.get("Vulnerabilities")
        except BaseException:
            raise ValueError("Invalid format")
        return subtree

    def set_items_for_severity(self, tree, test, severity):
        items = list()
        tree_severity = tree.get(severity)
        if tree_severity:
            for data in self.get_items_clairklar(tree_severity, test):
                items.append(data)
            logger.debug("Appended findings for severity " + severity)
        else:
            logger.debug("No findings for severity " + severity)
        return items

    def get_items_clair(self, tree, test):
        items = {}
        for node in tree:
            item = self.get_item_clair(node, test)
            unique_key = str(node["vulnerability"]) + str(node["featurename"])
            items[unique_key] = item
        return list(items.values())

    def get_item_clair(self, item_node, test):
        if (
            item_node["severity"] == "Negligible"
            or item_node["severity"] == "Unknown"
        ):
            severity = "Info"
        else:
            severity = item_node["severity"]

        finding = Finding(
            title=item_node["vulnerability"]
            + " - "
            + "("
            + item_node["featurename"]
            + ", "
            + item_node["featureversion"]
            + ")",
            test=test,
            severity=severity,
            description=item_node["description"]
            + "\n Vulnerable feature: "
            + item_node["featurename"]
            + "\n Vulnerable Versions: "
            + str(item_node["featureversion"])
            + "\n Fixed by: "
            + str(item_node["fixedby"])
            + "\n Namespace: "
            + str(item_node["namespace"])
            + "\n CVE: "
            + str(item_node["vulnerability"]),
            mitigation=item_node["fixedby"],
            references=item_node["link"],
            component_name=item_node["featurename"],
            component_version=item_node["featureversion"],
            false_p=False,
            duplicate=False,
            out_of_scope=False,
            mitigated=None,
            static_finding=True,
            dynamic_finding=False,
            impact="No impact provided",
        )
        if item_node["vulnerability"]:
            finding.unsaved_vulnerability_ids = [item_node["vulnerability"]]
        return finding

    def get_items_clairklar(self, tree_severity, test):
        items = {}
        for node in tree_severity:
            item = self.get_item_clairklar(node, test)
            unique_key = str(node["Name"]) + str(node["FeatureName"])
            items[unique_key] = item
        return items.values()

    def get_item_clairklar(self, item_node, test):
        if item_node["Severity"] == "Negligible":
            severity = "Info"
        elif item_node["Severity"] == "Unknown":
            severity = "Critical"
        elif item_node["Severity"] == "Defcon1":
            severity = "Critical"
        else:
            severity = item_node["Severity"]
        description = ""
        if "Description" in item_node:
            description += item_node["Description"] + "\n<br /> "
        if "FeatureName" in item_node:
            description += (
                "Vulnerable feature: " + item_node["FeatureName"] + "\n<br />"
            )
        if "FeatureVersion" in item_node:
            description += " Vulnerable Versions: " + str(
                item_node["FeatureVersion"]
            )

        mitigation = ""
        if "FixedBy" in item_node:
            description = description + "\n Fixed by: " + str(item_node["FixedBy"])
            mitigation = (
                "Please use version "
                + item_node["FixedBy"]
                + " of library "
                + item_node["FeatureName"]
            )
        else:
            mitigation = "A patch could not been found"

        link = ""
        if "Link" in item_node:
            link = item_node["Link"]

        finding = Finding(
            title=item_node["Name"]
            + " - "
            + "("
            + item_node["FeatureName"]
            + ", "
            + item_node["FeatureVersion"]
            + ")",
            test=test,
            severity=severity,
            description=description,
            mitigation=mitigation,
            references=link,
            false_p=False,
            duplicate=False,
            out_of_scope=False,
            mitigated=None,
            cwe=1035,  # Vulnerable Third Party Component
            static_finding=True,
            dynamic_finding=False,
            impact="No impact provided",
        )
        return finding
