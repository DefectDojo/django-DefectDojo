import json

from dojo.location.feature import locations_enabled
from dojo.models import Finding
from dojo.tools.locations import LocationData

# Polaris grades every check as danger, warning or ignore in its configuration.
SEVERITIES = {
    "DANGER": "High",
    "WARNING": "Medium",
    "IGNORE": "Info",
}
DEFAULT_SEVERITY = "Medium"

# Polaris audits either a set of manifests or a live cluster; only in the first case is SourceName a
# file path worth reporting as one.
PATH_SOURCE = "Path"


class PolarisParser:

    """Parses the JSON report produced by `polaris audit --format json`."""

    def get_scan_types(self):
        return ["Polaris Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Polaris Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import the JSON report produced by "
            "`polaris audit --audit-path <path> --format json`."
        )

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, dict):
            msg = f"A Polaris JSON report is an object; got a {type(data).__name__}."
            raise TypeError(msg)

        source = data.get("SourceName") if data.get("SourceType") == PATH_SOURCE else None

        findings = []
        for result in data.get("Results") or []:
            if not isinstance(result, dict):
                msg = "Every result in a Polaris report must be an object."
                raise TypeError(msg)
            findings.extend(self.findings_for_object(result, source, test))
        return findings

    def findings_for_object(self, result, source, test):
        """
        Walk the three levels Polaris nests its checks under.

        A check applies to the top-level object, to its pod template, or to one container inside
        that template, and each level keeps its results in its own map.
        """
        owner = self.owner(result)
        findings = list(self.findings_for_checks(result.get("Results"), owner, "object", None, source, test))

        pod_result = result.get("PodResult") or {}
        findings.extend(self.findings_for_checks(pod_result.get("Results"), owner, "pod", None, source, test))

        for container in pod_result.get("ContainerResults") or []:
            name = container.get("Name")
            findings.extend(
                self.findings_for_checks(container.get("Results"), owner, "container", name, source, test),
            )
        return findings

    def findings_for_checks(self, checks, owner, scope, container, source, test):
        for check_id, check in (checks or {}).items():
            # Polaris reports passing checks alongside failing ones, so only the failures are
            # findings. Importing everything would turn a clean manifest into dozens of findings.
            if not isinstance(check, dict) or check.get("Success"):
                continue
            yield self.build_finding(check_id, check, owner, scope, container, source, test)

    def owner(self, result):
        """Name the audited object as "Kind/name", namespaced when Polaris reported a namespace."""
        kind = result.get("Kind") or ""
        name = result.get("Name") or ""
        if not kind and not name:
            return ""
        owner = f"{kind}/{name}" if kind and name else (kind or name)
        if namespace := result.get("Namespace"):
            owner = f"{namespace}/{owner}"
        return owner

    def build_finding(self, check_id, check, owner, scope, container, source, test):
        component = f"{owner}/{container}" if owner and container else (owner or container or "")

        finding = Finding(
            test=test,
            title=check.get("Message") or check_id,
            severity=SEVERITIES.get((check.get("Severity") or "").upper(), DEFAULT_SEVERITY),
            description=self.build_description(check_id, check, owner, scope, container),
            file_path=source,
            component_name=component or None,
            static_finding=True,
            dynamic_finding=False,
            vuln_id_from_tool=check_id,
        )
        if locations_enabled() and source:
            # Polaris names the manifest it read but never a line inside it.
            finding.unsaved_locations.append(LocationData.code(file_path=source))
        return finding

    def build_description(self, check_id, check, owner, scope, container):
        parts = []
        if message := check.get("Message"):
            parts.append(message)
        parts.append(f"**Check:** {check_id}")
        if category := check.get("Category"):
            parts.append(f"**Category:** {category}")
        if severity := check.get("Severity"):
            parts.append(f"**Polaris severity:** {severity}")
        # The scope says whether the check is about the workload, its pod template or one container,
        # which is what tells a reader where the fix goes.
        parts.append(f"**Applies to:** {scope}")
        if owner:
            parts.append(f"**Object:** {owner}")
        if container:
            parts.append(f"**Container:** {container}")
        if details := check.get("Details"):
            parts.append(f"**Details:** {details}")
        return "\n".join(parts)
