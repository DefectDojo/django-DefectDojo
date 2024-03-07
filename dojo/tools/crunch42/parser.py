import json
from dojo.models import Finding


class Crunch42Parser(object):

    def get_scan_types(self):
        return ["Crunch42 Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Crunch42 Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON output of Crunch42 scan report."

    def parse_json(self, json_output):
        try:
            data = json_output.read()
            try:
                tree = json.loads(str(data, "utf-8"))
            except Exception:
                tree = json.loads(data)
        except Exception:
            raise ValueError("Invalid format")

        return tree

    def process_tree(self, tree, test):
        return list(self.get_items(tree, test)) if tree else []

    def get_findings(self, filename, test):
        reportTree = self.parse_json(filename)

        if isinstance(reportTree, list):
            temp = []
            for moduleTree in reportTree:
                temp += self.process_tree(moduleTree, test)
            return temp
        else:
            return self.process_tree(reportTree, test)

    def get_items(self, tree, test):
        items = {}
        iterator = 0
        if "report" in tree and tree["report"].get("security"):
            results = tree["report"].get("security").get("issues")
            for key, node in results.items():
                for issue in node["issues"]:
                    item = self.get_item(
                        issue, key, test
                    )
                    items[iterator] = item
                    iterator += 1
        return list(items.values())

    def get_item(self, issue, title, test):
        fingerprint = issue["fingerprint"]
        pointer = issue["pointer"]
        message = issue["specificDescription"] if 'specificDescription' in issue else title
        score = issue["score"]
        criticality = issue["criticality"]
        if criticality == 1:
            severity = "Info"
        elif criticality == 2:
            severity = "Low"
        elif criticality == 3:
            severity = "Medium"
        elif criticality <= 4:
            severity = "High"
        else:
            severity = "Critical"
        # create the finding object
        finding = Finding(
            unique_id_from_tool=fingerprint,
            title=title,
            test=test,
            severity=severity,
            description="**fingerprint**: " + str(fingerprint) + "\n"
            + "**pointer**: " + str(pointer) + "\n"
            + "**message**: " + str(message) + "\n"
            + "**score**: " + str(score) + "\n",
            false_p=False,
            duplicate=False,
            out_of_scope=False,
            static_finding=True,
            dynamic_finding=False,
        )
        return finding
