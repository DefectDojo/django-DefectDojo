import hashlib
import json
from datetime import datetime

from dojo.models import Endpoint, Finding


class WpscanParser(object):
    """WPScan - WordPress Security Scanner"""

    def get_scan_types(self):
        return ["Wpscan"]

    def get_label_for_scan_types(self, scan_type):
        return "Wpscan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON report"

    def get_vulnerabilities(
        self, report_date, vulnerabilities, dupes, node=None, plugin=None, detection_confidence=None
    ):
        for vul in vulnerabilities:
            description = "\n".join(["**Title:** `" + vul["title"] + "`\n"])

            if node and "location" in node:
                description += "**Location:** `" + "".join(node["location"]) + "`\n"

            if plugin:
                description += "**Plugin:** `" + "".join(plugin) + "`\n"

            finding = Finding(
                title=vul["title"],
                description=description,
                severity="Medium",
                cwe=1035,
                references=self.generate_references(vul["references"]),
                dynamic_finding=True,
                static_finding=False,
                scanner_confidence=self._get_scanner_confidence(detection_confidence),
                unique_id_from_tool=vul["references"]["wpvulndb"][0],
                nb_occurences=1,
            )
            if plugin:
                finding.component_name = plugin

            # manage version
            if node and "version" in node and node["version"] is not None:
                finding.component_version = node["version"].get("number")
            # manage date of finding with report date
            if report_date:
                finding.date = report_date
            # if there is a fixed version fill mitigation
            if "fixed_in" in vul and vul["fixed_in"]:
                finding.mitigation = "fixed in : " + vul["fixed_in"]
            # manage CVE
            if "cve" in vul["references"]:
                finding.unsaved_vulnerability_ids = list()
                for vulnerability_id in vul["references"]["cve"]:
                    finding.unsaved_vulnerability_ids.append(f"CVE-{vulnerability_id}")

            # internal de-duplication
            dupe_key = hashlib.sha256(str(finding.unique_id_from_tool).encode("utf-8")).hexdigest()
            if dupe_key in dupes:
                find = dupes[dupe_key]
                if finding.references:
                    dupes[dupe_key].references += finding.references
                find.nb_occurences += finding.nb_occurences
            else:
                dupes[dupe_key] = finding

    def get_findings(self, file, test):
        tree = json.load(file)

        report_date = None
        if "start_time" in tree:
            report_date = datetime.utcfromtimestamp(tree.get("start_time"))

        dupes = dict()
        # manage plugin findings
        for plugin in tree.get("plugins", []):
            node = tree["plugins"][plugin]
            self.get_vulnerabilities(
                report_date,
                node.get("vulnerabilities"),
                dupes,
                node,
                plugin,
                detection_confidence=node.get("confidence"),
            )

        # manage Wordpress version findings
        if "version" in tree and tree["version"]:
            if "vulnerabilities" in tree["version"] and tree["version"]["vulnerabilities"]:
                self.get_vulnerabilities(
                    report_date,
                    tree["version"]["vulnerabilities"],
                    dupes,
                    node=None,
                    plugin=None,
                    detection_confidence=tree["version"].get("confidence"),
                )

        # manage interesting interesting_findings
        for interesting_finding in tree.get("interesting_findings", []):
            references = self.generate_references(interesting_finding["references"])
            description = "\n".join(
                [
                    "**Type:** `" + interesting_finding.get("type") + "`\n",
                    "**Url:** `" + interesting_finding["url"] + "`\n",
                ]
            )
            if interesting_finding["interesting_entries"]:
                description += "**Details:** `" + " ".join(interesting_finding["interesting_entries"]) + "`\n"
            finding = Finding(
                title=f"Interesting finding: {interesting_finding.get('to_s')}",
                description=description,
                severity="Info",
                dynamic_finding=True,
                static_finding=False,
                scanner_confidence=self._get_scanner_confidence(interesting_finding.get("confidence")),
            )
            # manage endpoint
            endpoint = Endpoint.from_uri(interesting_finding["url"])

            finding.unsaved_endpoints = [endpoint]
            # manage date of finding with report date
            if report_date:
                finding.date = report_date

            # internal de-duplication
            dupe_key = hashlib.sha256(
                str("interesting_findings" + finding.title + interesting_finding["url"]).encode("utf-8")
            ).hexdigest()
            if dupe_key in dupes:
                find = dupes[dupe_key]
                if finding.references:
                    dupes[dupe_key].references += finding.references
                find.nb_occurences += finding.nb_occurences
            else:
                dupes[dupe_key] = finding

        return list(dupes.values())

    def generate_references(self, node):
        references = ""
        for ref in node:
            for item in node.get(ref, []):
                if ref == "url":
                    references += f"* [{item}]({item})\n"
                elif ref == "wpvulndb":
                    references += f"* [WPScan WPVDB](https://wpscan.com/vulnerability/{item})\n"
                else:
                    references += f"* {item} - {ref}\n"
        return references

    def _get_scanner_confidence(self, val):
        """Confidence value are from 0 (wrong) to 100 (certain)
        So we divide by 10 and invert axis
        """
        if val is None:
            return None
        val_raw = round(int(val) / 10)
        return 10 - val_raw
