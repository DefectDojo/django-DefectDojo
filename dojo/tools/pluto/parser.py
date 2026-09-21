import json

from dojo.models import Finding


class PlutoParser:

    """
    Parser for Pluto JSON reports.

    Pluto finds Kubernetes objects that use deprecated or removed API versions. An object on
    an API that has already been *removed* will not apply to a cluster at that version at all,
    which is more serious than one merely marked deprecated.
    """

    def get_scan_types(self):
        return ["Pluto Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Pluto reports in JSON format, generated with 'pluto detect-files -d . -o json'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for item in (data.get("items") or []):
            api = item.get("api", {})
            # Pluto lists every object it inspected; only the deprecated ones are findings.
            if not item.get("deprecated") and not item.get("removed"):
                continue
            findings.append(self._to_finding(item, api, test))
        return findings

    def _to_finding(self, item, api, test):
        name = item.get("name")
        kind = api.get("kind")
        version = api.get("version")
        removed = bool(item.get("removed"))
        replacement = api.get("replacement-api")

        state = "removed" if removed else "deprecated"
        description = [
            f"**Object:** {kind}/{name}",
            f"**API version:** {version}",
            f"**State:** {state}",
        ]
        if item.get("namespace"):
            description.insert(1, f"**Namespace:** {item['namespace']}")
        if api.get("deprecated-in"):
            description.append(f"**Deprecated in:** {api['deprecated-in']}")
        if api.get("removed-in"):
            description.append(f"**Removed in:** {api['removed-in']}")
        if replacement:
            description.append(f"**Replacement API:** {replacement}")
        if api.get("replacement-available-in"):
            description.append(f"**Replacement available in:** {api['replacement-available-in']}")
        if api.get("component"):
            description.append(f"**Component:** {api['component']}")

        mitigation = (
            f"Migrate {kind}/{name} from {version} to {replacement}."
            if replacement
            else f"Move {kind}/{name} off the {version} API."
        )

        return Finding(
            title=f"{state.capitalize()} API {version} used by {kind}/{name}",
            test=test,
            # An object on an API that is already gone will not apply at all.
            severity="High" if removed else "Medium",
            description="\n".join(description),
            mitigation=mitigation,
            file_path=item.get("filePath"),
            component_name=f"{kind}/{name}",
            component_version=version,
            vuln_id_from_tool=f"{version}/{kind}",
            static_finding=True,
            dynamic_finding=False,
        )
