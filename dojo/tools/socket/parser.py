import json

from dojo.models import Finding

# Mirrors toSeverity() in the Socket connector's converter. Socket's own ladder is
# low | middle | high | critical - note "middle", not "medium" - and anything unrecognised
# becomes Info there, so it does here too.
SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "middle": "Medium",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Info"


class SocketParser:

    """
    Parses a Socket full-scan artifact export.

    The scan type, title construction, severity ladder, component naming, unique id and tags are
    mirrored from the Socket connector's converter (pkg/tools/socket/converter) so that a file
    import and an API sync produce the same findings and deduplicate against each other. A customer
    who cannot grant Socket API credentials gets the same data by exporting the scan instead.
    """

    def get_scan_types(self):
        # MUST match the connector's ScanType() exactly, or file findings and API-synced findings
        # land in different test types and never deduplicate.
        return ["Socket - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Socket - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Socket full-scan artifact export (JSON). Matches the scan type used by the "
            "Socket connector so file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Socket Parser.

        Fields mirror the connector's converter:
        - title: "<alert type> in <component>".
        - severity: Socket's low/middle/high/critical ladder; anything else is Info.
        - description: Alert type, category, package URL, ecosystem and the alert props.
        - component_name: "<namespace>/<name>" when the artifact has a namespace, else the name.
        - component_version: Artifact version.
        - file_path: Alert file, when the alert names one.
        - unique_id_from_tool: Alert key, which is what the connector dedupes on.
        - tags: socket:<type>, category:<category>, ecosystem:<type> and the package URL.
        - static_finding: True, dynamic_finding: False - as the converter sets them.
        """
        return [
            "title",
            "severity",
            "description",
            "component_name",
            "component_version",
            "file_path",
            "unique_id_from_tool",
            "tags",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Socket Parser.

        The connector sets UniqueIDFromTool to the alert key, so that is the dedupe identity here
        too. Diverging would stop file findings merging with API-synced ones.
        """
        return ["unique_id_from_tool"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        artifacts = self.extract_artifacts(data)

        findings = {}
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            for alert in artifact.get("alerts") or []:
                if not isinstance(alert, dict):
                    continue
                key = alert.get("key") or ""
                # The connector's unique id is the alert key; two alerts sharing one are the same
                # finding.
                if key and key in findings:
                    continue
                finding = self.build_finding(alert, artifact, test)
                findings[key or id(alert)] = finding
        return list(findings.values())

    def extract_artifacts(self, data):
        """
        Accept either a bare list of artifacts or the API envelope that wraps them.

        Socket's full-scan endpoint streams artifacts, and what people save varies: a JSON array, or
        an object with the artifacts under "artifacts" or "results".
        """
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("artifacts", "results"):
                if isinstance(data.get(key), list):
                    return data[key]
            # A single artifact saved on its own.
            if "alerts" in data:
                return [data]
        msg = (
            "A Socket export is a JSON array of artifacts, or an object with an 'artifacts' or "
            f"'results' list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def build_finding(self, alert, artifact, test):
        component = self.component_name(artifact)
        purl = self.package_url(artifact)
        alert_type = alert.get("type") or "Unknown alert"

        finding = Finding(
            test=test,
            # converter: fmt.Sprintf("%s in %s", alert.Type, component)
            title=f"{alert_type} in {component}" if component else alert_type,
            severity=SEVERITY_MAP.get(
                (alert.get("severity") or "").strip().lower(), DEFAULT_SEVERITY,
            ),
            description=self.build_description(alert, artifact, purl),
            component_name=component or None,
            component_version=artifact.get("version") or None,
            unique_id_from_tool=alert.get("key") or None,
            # The converter marks Socket findings static: it reads a dependency manifest rather than
            # exercising a running application.
            static_finding=True,
            dynamic_finding=False,
        )
        if file_path := alert.get("file"):
            finding.file_path = file_path
        finding.unsaved_tags = self.build_tags(alert, artifact, purl)
        return finding

    def component_name(self, artifact):
        """converter: namespace + "/" + name when a namespace is present, else name."""
        name = artifact.get("name") or ""
        namespace = artifact.get("namespace") or ""
        return f"{namespace}/{name}" if namespace else name

    def package_url(self, artifact):
        """converter: pkg:<type>/<namespace>/<name>@<version>, empty when type or name is missing."""
        ecosystem = artifact.get("type") or ""
        name = artifact.get("name") or ""
        if not ecosystem or not name:
            return ""
        if namespace := artifact.get("namespace"):
            name = f"{namespace}/{name}"
        purl = f"pkg:{ecosystem}/{name}"
        if version := artifact.get("version"):
            purl += f"@{version}"
        return purl

    def build_description(self, alert, artifact, purl):
        parts = [
            f"**Socket alert:** {alert.get('type') or ''}",
            f"**Category:** {alert.get('category') or ''}",
        ]
        if purl:
            parts.append(f"**Package:** {purl}")
        if ecosystem := artifact.get("type"):
            parts.append(f"**Ecosystem:** {ecosystem}")
        # The converter renders the free-form alert props as sorted key/value lines.
        props = alert.get("props")
        if isinstance(props, dict):
            parts.extend(f"**{key}:** {props[key]}" for key in sorted(props))
        return "\n".join(parts)

    def build_tags(self, alert, artifact, purl):
        tags = [f"socket:{alert.get('type') or ''}"]
        if category := alert.get("category"):
            tags.append(f"category:{category}")
        if ecosystem := artifact.get("type"):
            tags.append(f"ecosystem:{ecosystem}")
        if purl:
            tags.append(purl)
        return tags
