import json

from dojo.location.feature import locations_enabled
from dojo.models import Finding
from dojo.tools.locations import LocationData

# KubeLinter does not grade its checks - a report carries no severity, score or confidence - and its
# default set mixes security checks (privileged-container, run-as-non-root) with reliability ones
# (no-anti-affinity, unset-cpu-requirements). Everything imports at one level and the docs page says
# to triage by check name, which is the finding title.
DEFAULT_SEVERITY = "Medium"


class KubeLinterParser:

    """Parses the JSON report produced by `kube-linter lint --format json`."""

    def get_scan_types(self):
        return ["KubeLinter Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "KubeLinter Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the JSON report produced by `kube-linter lint --format json <path>`."

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, dict):
            msg = f"A KubeLinter JSON report is an object; got a {type(data).__name__}."
            raise TypeError(msg)

        findings = []
        for report in data.get("Reports") or []:
            if not isinstance(report, dict):
                msg = "Every report in a KubeLinter report must be an object."
                raise TypeError(msg)
            findings.append(self.build_finding(report, test))
        return findings

    def build_finding(self, report, test):
        check = report.get("Check") or "KubeLinter check"
        obj = report.get("Object") or {}
        file_path = (obj.get("Metadata") or {}).get("FilePath")
        component = self.component(obj.get("K8sObject") or {})

        finding = Finding(
            test=test,
            title=str(check),
            severity=DEFAULT_SEVERITY,
            description=self.build_description(report, obj),
            # KubeLinter ships a remediation sentence with every check, which is exactly what the
            # mitigation field is for.
            mitigation=report.get("Remediation") or None,
            file_path=file_path,
            component_name=component or None,
            static_finding=True,
            dynamic_finding=False,
            vuln_id_from_tool=str(check),
        )
        if locations_enabled() and file_path:
            # KubeLinter reports the manifest but never a line number, so the location is the file.
            finding.unsaved_locations.append(LocationData.code(file_path=file_path))
        return finding

    def component(self, k8s_object):
        """Name the offending object as "Kind/name", namespaced when KubeLinter gave a namespace."""
        kind = (k8s_object.get("GroupVersionKind") or {}).get("Kind") or ""
        name = k8s_object.get("Name") or ""
        if not kind and not name:
            return ""
        component = f"{kind}/{name}" if kind and name else (kind or name)
        if namespace := k8s_object.get("Namespace"):
            component = f"{namespace}/{component}"
        return component

    def build_description(self, report, obj):
        parts = []
        if message := (report.get("Diagnostic") or {}).get("Message"):
            parts.append(message)
        if check := report.get("Check"):
            parts.append(f"**Check:** {check}")

        k8s_object = obj.get("K8sObject") or {}
        group_version_kind = k8s_object.get("GroupVersionKind") or {}
        if kind := group_version_kind.get("Kind"):
            api_version = "/".join(
                part for part in (group_version_kind.get("Group"), group_version_kind.get("Version")) if part
            )
            parts.append(f"**Object:** {kind}" + (f" ({api_version})" if api_version else ""))
        if name := k8s_object.get("Name"):
            parts.append(f"**Name:** {name}")
        # An empty namespace means the manifest did not set one, which is worth distinguishing from
        # a namespace that happens to be called "default".
        parts.append(f"**Namespace:** {k8s_object.get('Namespace') or '(not set)'}")
        if file_path := (obj.get("Metadata") or {}).get("FilePath"):
            parts.append(f"**Manifest:** {file_path}")
        return "\n".join(parts)
