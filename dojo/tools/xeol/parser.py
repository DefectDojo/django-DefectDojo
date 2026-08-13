import json
from datetime import datetime

from django.conf import settings

from dojo.models import Finding
from dojo.tools.locations import LocationData


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

            # Severity records whether the component is past its end-of-life date, and
            # deliberately does not grade how long ago that date fell.
            #
            # This used to band the age of the EOL date (Low/Medium/High inside 2/4/6
            # weeks, Critical beyond), which made the parser's output a function of the
            # calendar as well as of the report: the same unchanged scan produced a
            # different severity on a different day, walking one finding through four
            # severities over six weeks with no upstream event behind it. That churned
            # severity on every reimport, and on any instance whose hash fields include
            # severity it churned hash_code too, so reimport stopped matching stored
            # findings, closed them as absent and created duplicates. A parser's output
            # has to be reproducible from its input.
            #
            # One comparison against the current date remains, because "has this cycle
            # reached EOL" is a genuine state change rather than an escalation ladder: it
            # happens once per component, in one direction, on the date the report itself
            # names.
            severity = "Info"
            try:
                eol_date = datetime.strptime(cycle.get("Eol", ""), "%Y-%m-%d")
            except (TypeError, ValueError):
                pass
            else:
                if eol_date < datetime.now():
                    severity = "Critical"

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

            artifact_purl = artifact.get("purl")
            if settings.V3_FEATURE_LOCATIONS and artifact_purl:
                license_expression = " OR ".join(artifact.get("licenses", []))
                finding.unsaved_locations.append(
                    LocationData.dependency(purl=artifact_purl, license_expression=license_expression),
                )

            findings.append(finding)

        return findings
