import json

from dojo.models import Finding


class XeolParser:

    def get_scan_types(self):
        return ["Xeol Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Xeol Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import Xeol JSON output."

    def get_findings(self, file, test):
        tree = json.load(file)
        return self.get_items(tree, test)

    def get_items(self, tree, test):
        items = {}
        for match in tree.get("matches", []):
            artifact = match.get("artifact", {})
            cycle = match.get("cycle", {})

            name = artifact.get("name", "")
            version = artifact.get("version", "")
            purl = artifact.get("purl", "")
            cpe = artifact.get("cpe", "")

            title = f"{name} EOL Information"
            description = (
                f"**Artifact Name:** {name}\n"
                f"**Artifact Version:** {version}\n"
                f"**PURL:** {purl}\n"
                f"**CPE:** {cpe}\n"
                f"**Cycle:** {cycle.get('cycle', '')}\n"
                f"**Release Date:** {cycle.get('releaseDate', '')}\n"
                f"**EOL Date:** {cycle.get('eol', '')}\n"
                f"**Latest Release:** {cycle.get('latestRelease', '')}\n"
                f"**Latest Release Date:** "
                f"{cycle.get('latestReleaseDate', '')}\n"
            )

            severity = "Info"
            eol_val = cycle.get("Eol", "")
            if eol_val:
                if isinstance(eol_val, bool) and eol_val:
                    severity = "Critical"
                elif (
                    isinstance(eol_val, str)
                    and eol_val.lower() not in ["false", "none", ""]
                ):
                    severity = "Critical"

            unique_key = f"{name}-{version}-{cycle.get('cycle', '')}"

            if unique_key not in items:
                items[unique_key] = Finding(
                    title=title,
                    test=test,
                    severity=severity,
                    description=description,
                    cwe=672,
                    component_name=name,
                    component_version=version,
                    vuln_id_from_tool=f"EOL-{name}-{version}",
                    static_finding=True,
                    dynamic_finding=False,
                )

        return list(items.values())
