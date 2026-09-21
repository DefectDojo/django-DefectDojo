import json

from dojo.models import Finding


class KubeEyeParser:

    """
    Parser for KubeEye cluster inspection results.

    KubeEye writes an ``InspectResult`` whose ``spec`` holds one list per kind of inspection it
    ran -- node information, file changes, sysctl and systemd settings, command output, component
    health, service connectivity and Prometheus rules. Every entry in every one of those lists
    embeds the same three fields (``name``, ``assert``, ``level``) from KubeEye's ``BaseResult``,
    so they are all walked the same way and only the extra, per-kind fields differ.

    ``assert`` is the important one: KubeEye sets it to ``true`` when the inspection found the
    problem it was looking for, and sets ``level`` from the rule at the same moment. Entries with
    ``assert`` false are checks that passed and are not findings.
    """

    # apis/kubeeye/v1alpha2/inspectresult_types.go declares exactly three levels.
    SEVERITY = {
        "danger": "High",
        "warning": "Medium",
        "ignore": "Info",
    }
    DEFAULT_SEVERITY = "Medium"

    # spec key -> (human label, extra fields to promote into the description)
    RESULT_SECTIONS = {
        "nodeInfo": ("Node information", ("nodeName", "value", "mount", "type")),
        "fileChangeResult": ("File change", ("nodeName", "path")),
        "fileFilterResult": ("File filter", ("nodeName", "path")),
        "sysctlResult": ("Sysctl setting", ("nodeName", "value")),
        "systemdResult": ("Systemd unit", ("nodeName", "value")),
        "commandResult": ("Command", ("nodeName", "command", "value")),
        "componentResult": ("Component", ()),
        "serviceConnectResult": ("Service connectivity", ("namespace", "endpoint")),
        "prometheusResult": ("Prometheus rule", ("rule", "result")),
    }

    def get_scan_types(self):
        return ["KubeEye Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import KubeEye inspection results in JSON format, exported from a cluster with "
            "'kubectl get inspectresult <name> -o json'."
        )

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for result in self._iter_results(data):
            spec = result.get("spec") or {}
            cluster = (spec.get("inspectCluster") or {}).get("name")
            for section, (label, extra_fields) in self.RESULT_SECTIONS.items():
                for item in spec.get(section) or []:
                    if not item.get("assert"):
                        continue
                    findings.append(self._to_finding(item, label, extra_fields, cluster, test))
        return findings

    def _iter_results(self, data):
        """Accept a single InspectResult or a Kubernetes List of them."""
        if not isinstance(data, dict):
            return
        if isinstance(data.get("items"), list):
            for item in data["items"]:
                if isinstance(item, dict):
                    yield item
            return
        yield data

    def _to_finding(self, item, label, extra_fields, cluster, test):
        name = item.get("name") or label
        level = (item.get("level") or "").lower()

        description = [f"**Inspection:** {label}", f"**Rule:** {name}"]
        if level:
            description.append(f"**Level:** {level}")
        if cluster:
            description.append(f"**Cluster:** {cluster}")
        description.extend(
            f"**{field}:** {item[field]}"
            for field in extra_fields
            if item.get(field) not in {None, ""}
        )
        issues = [issue for issue in item.get("issues") or [] if issue]
        if issues:
            description.append("**Issues:**\n" + "\n".join(f"- {issue}" for issue in issues))

        return Finding(
            title=f"{label}: {name}",
            test=test,
            description="\n".join(description),
            severity=self.SEVERITY.get(level, self.DEFAULT_SEVERITY),
            component_name=item.get("nodeName") or item.get("namespace") or cluster or None,
            file_path=item.get("path") or None,
            vuln_id_from_tool=name,
            static_finding=True,
            dynamic_finding=False,
        )
