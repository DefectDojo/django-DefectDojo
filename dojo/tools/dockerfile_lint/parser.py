import json

from dojo.models import Finding


class DockerfileLintParser:

    """
    Parser for dockerfile_lint JSON reports.

    dockerfile_lint checks a Dockerfile against a rule set covering build correctness and
    image hygiene, including checks with security weight such as running as root, using the
    floating ``latest`` tag, and adding remote archives over the network.
    """

    # dockerfile_lint's own buckets, which double as its severity scale.
    SEVERITY = {
        "error": "High",
        "warn": "Medium",
        "info": "Low",
    }

    def get_scan_types(self):
        return ["dockerfile_lint Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import dockerfile_lint reports in JSON format, generated with 'dockerfile_lint -f Dockerfile -j'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for bucket, severity in self.SEVERITY.items():
            entries = (data.get(bucket) or {}).get("data") or []
            findings.extend(self._to_finding(entry, severity, test) for entry in entries)
        return findings

    def _to_finding(self, entry, severity, test):
        label = entry.get("label")
        message = entry.get("message")
        # dockerfile_lint uses -1 for rules that apply to the file rather than a line,
        # such as a required LABEL that is missing entirely.
        line = entry.get("line")
        if line is not None and int(line) < 0:
            line = None

        description = []
        if entry.get("description"):
            description.append(entry["description"])
        description.append(f"**Rule:** {label}")
        if line is not None:
            description.append(f"**Line:** {line}")
        if entry.get("lineContent"):
            description.append(f"**Line content:** `{entry['lineContent']}`")

        references = entry.get("reference_url")
        if isinstance(references, list):
            # dockerfile_lint splits some documentation links across list entries, which
            # rejoin into the anchor they came from.
            references = "".join(references)

        return Finding(
            title=f"{label}: {message}" if label else message,
            test=test,
            description="\n".join(description),
            severity=severity,
            line=line,
            vuln_id_from_tool=label,
            references=references or None,
            static_finding=True,
            dynamic_finding=False,
        )
