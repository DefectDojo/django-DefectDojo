import json

from dojo.models import Finding


class ClairParser(object):
    def get_scan_types(self):
        return ["Clair Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON reports of Docker image vulnerabilities."

    def get_findings(self, json_output, test):
        tree = self.parse_json(json_output)
        return self.get_items(tree, test)

    def parse_json(self, json_output):
        data = json_output.read()
        try:
            tree = json.loads(str(data, "utf-8"))
        except BaseException:
            tree = json.loads(data)
        return tree.get("vulnerabilities")

    def get_items(self, tree, test):
        items = {}

        for node in tree:
            item = get_item(tree[node], test)
            unique_key = str(tree[node]["name"]) + str(tree[node]["package"]["name"])
            items[unique_key] = item

        return list(items.values())


def get_item(item_node, test):
    if (
        item_node["severity"] == "unimportant"
        or item_node["normalized_severity"] == "Unknown"
    ):
        severity = "Info"
    else:
        severity = item_node["normalized_severity"]

    finding = Finding(
        title=item_node["name"]
        + " - "
        + "("
        + item_node["package"]["name"]
        + ", "
        + item_node["package"]["version"]
        + ")",
        test=test,
        severity=severity,
        description=item_node["description"]
        + "\n Vulnerable feature: "
        + item_node["package"]["name"]
        + "\n Vulnerable Versions: "
        + str(item_node["package"]["version"])
        + "\n Fixed by: "
        + str(item_node["fixed_in_version"])
        + "\n CVE: "
        + str(item_node["name"]),
        mitigation=item_node["fixed_in_version"],
        references=item_node["links"],
        component_name=item_node["package"]["name"],
        component_version=item_node["package"]["version"],
        false_p=False,
        duplicate=False,
        out_of_scope=False,
        mitigated=None,
        static_finding=True,
        dynamic_finding=False,
        impact="No impact provided",
    )

    if item_node["name"]:
        finding.unsaved_vulnerability_ids = [item_node["name"]]

    return finding
