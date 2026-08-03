import json
from pathlib import PurePosixPath

from dojo.models import Finding

# Kingfisher emits no severity field, so severity is derived here from the two signals it does
# report. A credential Kingfisher validated as live is the most serious thing a secret scanner can
# say, so it outranks confidence entirely.
VALIDATION_SEVERITY = {
    # Kingfisher reached the provider and the credential worked.
    "active": "Critical",
    # Kingfisher reached the provider and the credential was rejected. The secret is still in the
    # source and still wants removing from history, so this stays a real finding rather than Info.
    "inactive": "Low",
}
# Used when validation was skipped, unknown, or never attempted (`--no-validate`).
CONFIDENCE_SEVERITY = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Medium"

# Every finding here is an exposed credential. Matches the CWE the trufflehog, trufflehog3,
# gitleaks and detect_secrets parsers already use, so secret findings agree across tools.
CWE_HARDCODED_CREDENTIALS = 798


class KingfisherParser:

    """
    Parses a Kingfisher secret-scanning report.

    Two things about this format are worth knowing:

    - `--format json` writes TWO concatenated JSON documents: the findings, then a run summary.
      `json.load()` raises "Extra data" on that, so the whole stream is walked instead.
    - `--format jsonl` writes one finding per line and then that same summary object as a final
      line, which has to be skipped rather than parsed as a finding.

    The detected secret is deliberately NOT copied into the finding. Kingfisher reports the path,
    line and column, which is enough to locate it, and copying the credential would duplicate it
    into the DefectDojo database.
    """

    def get_scan_types(self):
        return ["Kingfisher Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Kingfisher Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Kingfisher secret-scanning report "
            "(`kingfisher scan <target> --format json`). JSON and JSON Lines are both accepted. "
            "The detected secret value is not imported."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Kingfisher Parser.

        - title: the rule name, plus the file the secret was found in.
        - severity: Critical when Kingfisher validated the credential as live, otherwise derived
          from its confidence. See VALIDATION_SEVERITY and CONFIDENCE_SEVERITY.
        - description: rule, location, confidence, entropy and validation status - never the secret.
        - file_path / line: the location Kingfisher reports.
        - cwe: always 798, use of hard-coded credentials.
        - vuln_id_from_tool: the Kingfisher rule id, e.g. kingfisher.aws.1.
        - unique_id_from_tool: Kingfisher's own per-finding fingerprint.
        """
        return [
            "title",
            "severity",
            "description",
            "file_path",
            "line",
            "cwe",
            "vuln_id_from_tool",
            "unique_id_from_tool",
            "tags",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Kingfisher Parser.

        Kingfisher gives each finding a fingerprint, which is carried as unique_id_from_tool and is
        the primary identity. These hash fields are the fallback; the volatile description is
        deliberately excluded from them.
        """
        return ["title", "cwe", "file_path", "line"]

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")

        findings = []
        for document in self.documents(content):
            findings.extend(
                self.build_finding(entry, test) for entry in self.entries(document)
            )
        return findings

    def documents(self, content):
        """
        Yield every JSON document in the stream.

        Both Kingfisher formats put more than one document in a single file, so this walks the text
        with raw_decode rather than calling json.load on the whole thing.
        """
        decoder = json.JSONDecoder()
        index, length = 0, len(content)
        decoded_any = False
        while index < length:
            while index < length and content[index].isspace():
                index += 1
            if index >= length:
                break
            try:
                document, index = decoder.raw_decode(content, index)
            except json.JSONDecodeError as error:
                if not decoded_any:
                    msg = (
                        "A Kingfisher report is JSON or JSON Lines produced by "
                        f"`kingfisher scan --format json`; could not parse it ({error.msg})."
                    )
                    raise TypeError(msg) from error
                # Trailing junk after at least one good document is not worth failing the import.
                break
            decoded_any = True
            yield document

    def entries(self, document):
        """Pick the finding objects out of a document, skipping Kingfisher's run summary."""
        if not isinstance(document, dict):
            return []
        # The findings document from --format json.
        if isinstance(document.get("findings"), list):
            return [e for e in document["findings"] if isinstance(e, dict)]
        # A single finding line from --format jsonl. The summary line also carries a "findings"
        # key, but as an integer count, so it falls through to here and is skipped.
        if isinstance(document.get("rule"), dict) and isinstance(document.get("finding"), dict):
            return [document]
        return []

    def build_finding(self, entry, test):
        rule = entry.get("rule") or {}
        detail = entry.get("finding") or {}

        rule_name = rule.get("name") or "Secret"
        rule_id = rule.get("id")
        path = detail.get("path")
        confidence = (detail.get("confidence") or "").strip().lower()
        status = (detail.get("validation") or {}).get("status") or ""

        finding = Finding(
            test=test,
            title=self.title(rule_name, path),
            severity=self.severity(confidence, status),
            description=self.describe(rule_name, rule_id, detail, confidence, status),
            file_path=path or None,
            line=detail.get("line") or None,
            cwe=CWE_HARDCODED_CREDENTIALS,
            vuln_id_from_tool=rule_id,
            unique_id_from_tool=detail.get("fingerprint"),
            static_finding=True,
            dynamic_finding=False,
        )
        finding.unsaved_tags = ["secret"]
        if rule_id:
            finding.unsaved_tags.append(f"rule:{rule_id}")
        if confidence:
            finding.unsaved_tags.append(f"confidence:{confidence}")
        if status:
            finding.unsaved_tags.append(f"validation:{status.strip().lower().replace(' ', '-')}")
        return finding

    def title(self, rule_name, path):
        if path:
            return f"{rule_name} found in {PurePosixPath(path).name}"
        return rule_name

    def severity(self, confidence, status):
        validated = VALIDATION_SEVERITY.get(status.strip().lower())
        if validated:
            return validated
        return CONFIDENCE_SEVERITY.get(confidence, DEFAULT_SEVERITY)

    def describe(self, rule_name, rule_id, detail, confidence, status):
        lines = [f"**Rule:** {rule_name}"]
        if rule_id:
            lines.append(f"**Rule ID:** {rule_id}")

        location = detail.get("path") or ""
        if location and detail.get("line"):
            location = f"{location}:{detail['line']}"
            if detail.get("column_start"):
                location = f"{location}:{detail['column_start']}"
        if location:
            lines.append(f"**Location:** {location}")

        if confidence:
            lines.append(f"**Confidence:** {confidence}")
        if detail.get("entropy"):
            lines.append(f"**Entropy:** {detail['entropy']}")
        if status:
            lines.append(f"**Validation:** {status}")
        if (detail.get("language") or "").strip() not in {"", "Unknown"}:
            lines.append(f"**Language:** {detail['language']}")

        lines.append(
            "\nThe detected secret is not copied into this finding. Use the location above to find "
            "it, then revoke and rotate the credential and purge it from version-control history.",
        )
        return "\n".join(lines)
