import json

from dojo.models import Finding


class N0s1Parser:
    def get_scan_types(self):
        return ["n0s1 Scanner"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "JSON output from the n0s1 scanner."

    def get_findings(self, filename, test):
        dupes = {}
        tree = filename.read()
        try:
            data = json.loads(str(tree, "utf-8"))
        except Exception:
            data = json.loads(tree)

        # Load global regex rules
        regex_configs = {}
        if "regex_config" in data and "rules" in data["regex_config"]:
            for rule in data["regex_config"]["rules"]:
                regex_configs[rule["id"]] = rule

        # Iterate over findings
        for finding_id, finding_data in data.get("findings", {}).items():
            details = finding_data.get("details", {})
            regex_ref = details.get("matched_regex_config", {})
            regex_id = regex_ref.get("id")

            # Merge global config with local override
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
                test=test,
                description=description,
                severity="High",  # Adjust if needed
                dynamic_finding=True,
                static_finding=False,
                unique_id_from_tool=dupe_key,
            )
            dupes[dupe_key] = finding
        return list(dupes.values())
