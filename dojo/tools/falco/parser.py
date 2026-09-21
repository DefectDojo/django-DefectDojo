import json

from dojo.models import Finding


class FalcoParser:

    """
    Parser for Falco, the CNCF runtime security engine.

    Falco watches kernel events and raises an alert whenever one matches a rule, so its output is
    a stream of events rather than a set of static defects. One alert becomes one Finding here:
    each alert is a distinct thing that happened, at a time, in a container, to a file, by a
    process, and collapsing them on the way in would throw that away. Repeats of the same rule
    against the same workload are folded together afterwards by deduplication, which is keyed on
    the rule and the container rather than on the timestamp.

    ``json_output=true`` writes one JSON object per line; a JSON array of the same objects is
    also accepted, since some Falco outputs batch alerts that way.
    """

    # Falco priorities are the syslog levels, highest first, and are documented at
    # https://falco.org/docs/concepts/rules/basic-elements/#priority
    SEVERITY = {
        "emergency": "Critical",
        "alert": "Critical",
        "critical": "Critical",
        "error": "High",
        "warning": "Medium",
        "notice": "Low",
        "informational": "Info",
        "info": "Info",
        "debug": "Info",
    }
    DEFAULT_SEVERITY = "Medium"

    # output_fields worth promoting into the description, in the order an analyst reads them.
    CONTEXT_FIELDS = (
        ("container.name", "Container"),
        ("container.image.repository", "Image"),
        ("container.image.tag", "Image tag"),
        ("k8s.ns.name", "Kubernetes namespace"),
        ("k8s.pod.name", "Kubernetes pod"),
        ("proc.name", "Process"),
        ("proc.cmdline", "Command line"),
        ("proc.exepath", "Executable"),
        ("proc.pname", "Parent process"),
        ("user.name", "User"),
        ("user.uid", "User id"),
        ("fd.name", "File or connection"),
        ("evt.type", "Event type"),
    )

    def get_scan_types(self):
        return ["Falco Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Falco alerts in JSON format, generated with 'falco -o json_output=true'."

    def get_findings(self, file, test):
        content = file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")

        return [self._to_finding(alert, test) for alert in self._iter_alerts(content)]

    def _iter_alerts(self, content):
        """Accept both a JSON array of alerts and Falco's default one-object-per-line output."""
        stripped = content.strip()
        if not stripped:
            return
        if stripped.startswith("["):
            for alert in json.loads(stripped):
                if alert:
                    yield alert
            return
        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if line:
                yield json.loads(line)

    def _to_finding(self, alert, test):
        rule = alert.get("rule") or "Falco alert"
        priority = alert.get("priority") or ""
        fields = alert.get("output_fields") or {}

        description = []
        if alert.get("output"):
            description.append(alert["output"])
        description.extend((f"**Rule:** {rule}", f"**Priority:** {priority}"))
        if alert.get("source"):
            description.append(f"**Event source:** {alert['source']}")
        if alert.get("hostname"):
            description.append(f"**Host:** {alert['hostname']}")
        if alert.get("time"):
            description.append(f"**Time:** {alert['time']}")
        description.extend(
            f"**{label}:** {fields[key]}"
            for key, label in self.CONTEXT_FIELDS
            if fields.get(key) is not None
        )

        # The workload the alert is about: the container if there is one, otherwise the host.
        component = fields.get("container.name") or alert.get("hostname")

        finding = Finding(
            title=rule,
            test=test,
            description="\n".join(description),
            severity=self.SEVERITY.get(priority.lower(), self.DEFAULT_SEVERITY),
            component_name=component,
            file_path=fields.get("fd.name") or None,
            vuln_id_from_tool=rule,
            static_finding=False,
            dynamic_finding=True,
        )
        # Falco tags carry the MITRE technique ids and the rule's maturity level.
        finding.unsaved_tags = [str(tag) for tag in alert.get("tags") or []]
        return finding
