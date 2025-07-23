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

        if not isinstance(data, dict) or "results" not in data:
            return findings

        for result in data["results"]:
            image = result.get("image", "Unknown Image")
            matches = result.get("Matches", {})
            artifact = result.get("artifact", {})
            distro = result.get("distro", {})

            title = f"{matches.get('ProductName', 'Unknown Product')} EOL Information"
            description_lines = [
                f"**Image:** {image}",
                f"**Product Name:** {matches.get('ProductName', 'N/A')}",
                f"**Release Cycle:** {matches.get('ReleaseCycle', 'N/A')}",
                f"**EOL Date:** {matches.get('Eol', 'N/A')}",
                f"**Latest Release Date:** {matches.get('LatestReleaseDate', 'N/A')}",
                f"**Release Date:** {matches.get('ReleaseDate', 'N/A')}",
                f"**Artifact Name:** {artifact.get('name', 'N/A')}",
                f"**Artifact Version:** {artifact.get('version', 'N/A')}",
                f"**Artifact Type:** {artifact.get('type', 'N/A')}",
                f"**Licenses:** {', '.join(artifact.get('licenses', []))}",
                f"**Package URL:** {artifact.get('purl', 'N/A')}",
                f"**Distro Name:** {distro.get('name', 'N/A')}",
                f"**Distro Version:** {distro.get('version', 'N/A')}",
            ]

            locations = artifact.get("locations", [])
            location_info = []
            for loc in locations:
                path = loc.get("path", "")
                layer_id = loc.get("layerID", "")
                location_info.append(f"Path: {path}, LayerID: {layer_id}")
            if location_info:
                description_lines.append("**Locations:**\n" + "\n".join(location_info))

            description = "\n".join(description_lines)

            # Determine severity based on EOL date
            severity = "Info"
            eol_str = matches.get("Eol", "")
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
                references=matches.get("ProductPermalink", ""),
            )

            findings.append(finding)

        return findings
