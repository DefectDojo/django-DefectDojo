import json
from dojo.tools.clair.clair_parser import ClairScan
from dojo.tools.clair.clairklar_parser import ClairKlarScan


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
                return ClairScan().get_items_clair(tree, test)
            elif self.scanner == "clairklar":
                return ClairKlarScan().get_items_klar(tree, test)
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
