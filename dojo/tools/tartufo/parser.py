import json

from dojo.models import Finding


class TartufoParser:

    """
    Parser for Tartufo JSON reports.

    Tartufo scans git history for secrets, so a finding names not just the file but the commit
    that introduced the string and the branch it is on. A secret in history is treated as
    High, since rewriting history does not undo the exposure — the credential must be rotated.
    """

    def get_scan_types(self):
        return ["Tartufo Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Tartufo reports in JSON format, generated with 'tartufo --output-format json scan-local-repo <repo>'."

    def get_findings(self, file, test):
        data = json.load(file)
        return [self._to_finding(issue, test) for issue in data.get("found_issues", [])]

    def _to_finding(self, issue, test):
        detail = issue.get("issue_detail")
        issue_type = issue.get("issue_type")
        file_path = issue.get("file_path")

        description = []
        if detail:
            description.append(f"**Detected:** {detail}")
        if issue_type:
            description.append(f"**Match type:** {issue_type}")
        if file_path:
            description.append(f"**File:** {file_path}")
        if issue.get("branch"):
            description.append(f"**Branch:** {issue['branch']}")
        if issue.get("commit_hash"):
            description.append(f"**Commit:** {issue['commit_hash']}")
        if issue.get("commit_message"):
            description.append(f"**Commit message:** {issue['commit_message'].strip()}")
        if issue.get("commit_time"):
            description.append(f"**Commit time:** {issue['commit_time']}")

        return Finding(
            title=f"{detail or issue_type} in {file_path}" if file_path else (detail or issue_type),
            test=test,
            description="\n".join(description),
            # A secret already in git history stays exposed until it is rotated.
            severity="High",
            file_path=file_path,
            # Tartufo's signature is a stable hash of the match, so a re-scan tracks it.
            unique_id_from_tool=issue.get("signature"),
            vuln_id_from_tool=issue_type,
            mitigation=(
                "Rotate the exposed credential. Removing it from history does not undo the "
                "exposure, so the secret must be considered compromised."
            ),
            static_finding=True,
            dynamic_finding=False,
        )
