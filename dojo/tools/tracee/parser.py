import json

from dojo.models import Finding


class TraceeParser:

    """
    Parser for Tracee, Aqua Security's eBPF runtime security tracer.

    Tracee emits two quite different kinds of record on the same stream, and the difference
    decides what a Finding means here:

    - A **signature detection** is Tracee concluding that observed behaviour matches a known
      threat. It carries a ``metadata`` block with a signature id, a MITRE technique and a
      severity. These are detections, and are imported with the severity Tracee assigned.
    - A **traced event** is a raw syscall or LSM hook that matched the policy the operator asked
      Tracee to trace, such as ``security_inode_unlink`` or ``setuid``. Tracee is not claiming
      anything is wrong: the operator asked to see these. They are imported as Info so the
      activity is recorded without inventing a verdict Tracee never made.

    One record becomes one Finding. Repeats of the same signature or event against the same
    workload are folded together afterwards by deduplication, which is keyed on the event name
    and the container rather than on the timestamp.

    ``--output json`` writes one JSON object per line; a JSON array is also accepted.
    """

    # tracee/api/v1beta1/threat.proto: INFO=0 LOW=1 MEDIUM=2 HIGH=3 CRITICAL=4
    SIGNATURE_SEVERITY = {
        0: "Info",
        1: "Low",
        2: "Medium",
        3: "High",
        4: "Critical",
    }
    # A traced event is telemetry the operator opted into, not a verdict.
    TRACED_EVENT_SEVERITY = "Info"

    def get_scan_types(self):
        return ["Tracee Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Tracee events in JSON format, generated with 'tracee --output json'."

    def get_findings(self, file, test):
        content = file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")

        findings = []
        for event in self._iter_events(content):
            # Tracee interleaves its own structured log lines on the same stream; they have a
            # "level" and no event name, and are not findings.
            if event.get("eventName") is None:
                continue
            findings.append(self._to_finding(event, test))
        return findings

    def _iter_events(self, content):
        stripped = content.strip()
        if not stripped:
            return
        if stripped.startswith("["):
            for event in json.loads(stripped):
                if event:
                    yield event
            return
        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if line:
                yield json.loads(line)

    def _signature_properties(self, event):
        """Return the signature metadata properties, or None for a plain traced event."""
        properties = ((event.get("metadata") or {}).get("Properties")) or {}
        return properties or None

    @staticmethod
    def _get(mapping, *names):
        """Tracee's metadata uses Go field casing; be tolerant of either form."""
        for name in names:
            if mapping.get(name) is not None:
                return mapping[name]
        return None

    def _to_finding(self, event, test):
        event_name = event.get("eventName")
        container = event.get("container") or {}
        properties = self._signature_properties(event)

        description = []
        if (event.get("metadata") or {}).get("Description"):
            description.append(event["metadata"]["Description"])

        description.append(f"**Event:** {event_name}")
        for key, label in (
            ("syscall", "Syscall"),
            ("processName", "Process"),
            ("processId", "Process id"),
            ("hostProcessId", "Host process id"),
            ("userId", "User id"),
            ("returnValue", "Return value"),
            ("hostName", "Host"),
        ):
            if event.get(key) is not None:
                description.append(f"**{label}:** {event[key]}")
        if (event.get("executable") or {}).get("path"):
            description.append(f"**Executable:** {event['executable']['path']}")
        for key, label in (("name", "Container"), ("image", "Image"), ("id", "Container id")):
            if container.get(key):
                description.append(f"**{label}:** {container[key]}")
        kubernetes = event.get("kubernetes") or {}
        for key, label in (("podName", "Kubernetes pod"), ("podNamespace", "Kubernetes namespace")):
            if kubernetes.get(key):
                description.append(f"**{label}:** {kubernetes[key]}")

        matched = [policy for policy in event.get("matchedPolicies") or [] if policy]
        if matched:
            description.append(f"**Matched policies:** {', '.join(matched)}")

        arguments = [
            f"- `{argument.get('name')}` = {argument.get('value')}"
            for argument in event.get("args") or []
            if argument.get("name")
        ]
        if arguments:
            description.append("**Arguments:**\n" + "\n".join(arguments))

        severity = self.TRACED_EVENT_SEVERITY
        title = f"Traced event: {event_name}"
        tags = []
        mitre_id = None
        signature_id = None
        if properties:
            signature_id = self._get(properties, "signatureID", "signatureId")
            signature_name = self._get(properties, "signatureName")
            severity = self.SIGNATURE_SEVERITY.get(
                self._get(properties, "Severity", "severity"), "Medium",
            )
            title = str(signature_name or event_name)
            if signature_id:
                title = f"{signature_id}: {title}"
            mitre_id = self._get(properties, "external_id", "externalId")
            for key, label in (("Category", "Category"), ("Technique", "MITRE technique")):
                value = self._get(properties, key)
                if value:
                    description.append(f"**{label}:** {value}")
            if mitre_id:
                description.append(f"**MITRE id:** {mitre_id}")
                tags.append(str(mitre_id))
            tags.extend(str(tag) for tag in (event.get("metadata") or {}).get("Tags") or [])

        finding = Finding(
            title=title,
            test=test,
            description="\n".join(description),
            severity=severity,
            component_name=container.get("name") or event.get("hostName"),
            component_version=container.get("image") or None,
            vuln_id_from_tool=signature_id or event_name,
            static_finding=False,
            dynamic_finding=True,
        )
        finding.unsaved_tags = tags
        return finding
