import json

from dojo.models import Finding


class KingfisherParser:

    """
    Parser for Kingfisher JSON reports.

    Kingfisher does not grade its findings with a severity. It reports a confidence for the
    match and, where it can reach the provider, the result of actively validating the
    credential. A credential Kingfisher confirmed is live is treated as Critical; everything
    else falls back to the match confidence.
    """

    # Kingfisher's match-confidence scale, used when validation did not confirm a live credential.
    CONFIDENCE = {
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }

    def get_scan_types(self):
        return ["Kingfisher Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Kingfisher reports in JSON format, generated with 'kingfisher scan --format json'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for entry in data.get("findings", []):
            rule = entry.get("rule", {})
            match = entry.get("finding", {})
            validation = match.get("validation") or {}
            status = validation.get("status")
            # Kingfisher pads some paths it collected from the filesystem.
            path = (match.get("path") or "").strip() or None

            description = [f"**Rule:** {rule.get('name')}"]
            if match.get("confidence"):
                description.append(f"**Confidence:** {match['confidence']}")
            if status:
                description.append(f"**Validation:** {status}")
            if match.get("entropy"):
                description.append(f"**Entropy:** {match['entropy']}")
            if match.get("language"):
                description.append(f"**Language:** {match['language']}")
            if path:
                description.append(f"**Path:** {path}")

            finding = Finding(
                title=rule.get("name"),
                test=test,
                description="\n".join(description),
                severity=self._severity(status, match.get("confidence")),
                file_path=path,
                line=match.get("line"),
                vuln_id_from_tool=rule.get("id"),
                # The fingerprint is Kingfisher's own stable identity for a match.
                unique_id_from_tool=match.get("fingerprint"),
                mitigation=(
                    "Revoke and rotate the credential, then remove it from the source history."
                ),
                static_finding=True,
                dynamic_finding=False,
            )
            findings.append(finding)
        return findings

    def _severity(self, status, confidence):
        # Kingfisher reports the provider's own wording, e.g. "Active Credential".
        if status and "active" in status.lower() and "inactive" not in status.lower():
            return "Critical"
        return self.CONFIDENCE.get(str(confidence).lower(), "Medium")
