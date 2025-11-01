
import json

from dojo.models import Finding
from dojo.tools.parser_test import ParserTest


class N0s1Parser:
    def get_scan_types(self):
        return ["n0s1 Scanner"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "JSON output from the n0s1 scanner."

    def get_tests(self, scan_type, handle):
        data = json.load(handle)
        subscanner = self.detect_subscanner(data)
        test = ParserTest(
            name=subscanner,
            parser_type=subscanner,
            version=data.get("tool", {}).get("version", ""),
            description=f"Scan from {subscanner}",
        )
        test.findings = self.get_findings_from_data(data)
        return [test]

    def get_findings(self, scan_file, test):
        data = json.load(scan_file)
        return self.get_findings_from_data(data)

    def detect_subscanner(self, data):
        platforms = {f.get("details", {}).get("platform", "") for f in data.get("findings", {}).values()}
        if "Confluence" in platforms:
            return "n0s1 Confluence"
        if "GitHub" in platforms:
            return "n0s1 GitHub"
        if "GitLab" in platforms:
            return "n0s1 GitLab"
        return "n0s1"

    def get_findings_from_data(self, data):
        dupes = {}
        regex_configs = {}
        if "regex_config" in data and "rules" in data["regex_config"]:
            for rule in data["regex_config"]["rules"]:
                regex_configs[rule["id"]] = rule
        for finding_id, finding_data in data.get("findings", {}).items():
            details = finding_data.get("details", {})
            regex_ref = details.get("matched_regex_config", {})
            regex_id = regex_ref.get("id")
            regex_info = regex_configs.get(regex_id, {})
            merged_regex = {
                "id": regex_id,
                "description": regex_ref.get("description", regex_info.get("description", "N/A")),
                "regex": regex_ref.get("regex", regex_info.get("regex", "N/A")),
                "keywords": regex_info.get("keywords", []),
                "tags": regex_info.get("tags", []),
            }
            title = merged_regex["id"] or "n0s1 Finding"
            description = f"**URL:** {finding_data.get('url', 'N/A')}\n"
            description += f"**Secret:** {finding_data.get('secret', 'N/A')}\n"
            description += f"**Platform:** {details.get('platform', 'N/A')}\n"
            description += f"**Ticket Field:** {details.get('ticket_field', 'N/A')}\n"
            description += f"**Regex ID:** {merged_regex['id']}\n"
            description += f"**Regex Description:** {merged_regex['description']}\n"
            description += f"**Regex Pattern:** {merged_regex['regex']}\n"
            if merged_regex["keywords"]:
                description += f"**Keywords:** {', '.join(merged_regex['keywords'])}\n"
            if merged_regex["tags"]:
                description += f"**Tags:** {', '.join(merged_regex['tags'])}\n"
            dupe_key = finding_data.get("id", finding_id)
            if dupe_key in dupes:
                continue
            finding = Finding(
                title=title,
                description=description,
                severity="High",
                dynamic_finding=True,
                static_finding=False,
                unique_id_from_tool=dupe_key,
            )
            dupes[dupe_key] = finding
        return list(dupes.values())
