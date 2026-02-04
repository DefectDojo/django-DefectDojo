import logging

from dojo.models import Finding

logger = logging.getLogger(__name__)


class ClairScan:
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
