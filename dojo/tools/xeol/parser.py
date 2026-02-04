import json
from datetime import datetime, timedelta

from dojo.models import Finding


class XeolParser:
    def get_scan_types(self):
        return ["Xeol Parser"]

    def get_label_for_scan_types(self, scan_type):
        return "Xeol Parser"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON report"

    def get_findings(self, file, test):
        findings = []
        data = json.load(file)

        if not isinstance(data, dict) or "matches" not in data:
            return findings

        distro = data.get("distro", {})
        for match in data["matches"]:
            cycle = match.get("Cycle", {})
            artifact = match.get("artifact", {})

            title = f"{cycle.get('ProductName', 'Unknown Product')} EOL Information"

            description_lines = [
                f"**Product Name:** {cycle.get('ProductName', 'N/A')}",
                f"**Release Cycle:** {cycle.get('ReleaseCycle', 'N/A')}",
                f"**EOL Date:** {cycle.get('Eol', 'N/A')}",
                f"**Latest Release Date:** {cycle.get('LatestReleaseDate', 'N/A')}",
                f"**Release Date:** {cycle.get('ReleaseDate', 'N/A')}",
                f"**Artifact Name:** {artifact.get('name', 'N/A')}",
                f"**Artifact Version:** {artifact.get('version', 'N/A')}",
                f"**Artifact Type:** {artifact.get('type', 'N/A')}",
                f"**Licenses:** {', '.join(artifact.get('licenses', [])) if artifact.get('licenses') else 'N/A'}",
                f"**Package URL:** {artifact.get('purl', 'N/A')}",
                f"**CPEs:** {', '.join(artifact.get('cpes', [])) if artifact.get('cpes') else 'N/A'}",
                f"**Distro Name:** {distro.get('name', 'N/A')}",
                f"**Distro Version:** {distro.get('version', 'N/A')}",
            ]

            locations = artifact.get("locations", [])
            if locations:
                location_info = [
                    f"Path: {loc.get('path', '')}, LayerID: {loc.get('layerID', '')}"
                    for loc in locations
                ]
                description_lines.append("**Locations:**\n" + "\n".join(location_info))

            metadata = artifact.get("metadata", {})
            if isinstance(metadata, dict) and "files" in metadata:
                file_paths = [f.get("path", "") for f in metadata["files"] if "path" in f]
                if file_paths:
                    description_lines.append("**Files:**\n" + "\n".join(file_paths))

            description = "\n".join(description_lines)

            # Determine severity based on EOL date
            severity = "Info"
            eol_str = cycle.get("Eol", "")
            try:
                eol_date = datetime.strptime(eol_str, "%Y-%m-%d")
                now = datetime.now()
                if eol_date < now:
                    delta = now - eol_date
                    if delta <= timedelta(weeks=2):
                        severity = "Low"
                    elif delta <= timedelta(weeks=4):
                        severity = "Medium"
                    elif delta <= timedelta(weeks=6):
                        severity = "High"
                    else:
                        severity = "Critical"
            except Exception:
                severity = "Info"

            finding = Finding(
                title=title,
                test=test,
                severity=severity,
                description=description,
                component_name=artifact.get("name", ""),
                component_version=artifact.get("version", ""),
                static_finding=True,
                dynamic_finding=False,
                nb_occurences=1,
                cwe=672,
                references=cycle.get("ProductPermalink", "") + "\n[www.xeol.io/explorer](https://www.xeol.io/explorer)",
            )

            findings.append(finding)

        return findings
