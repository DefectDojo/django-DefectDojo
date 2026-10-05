import hashlib
import json

from dojo.location.feature import locations_enabled
from dojo.models import Finding
from dojo.tools.locations import LocationData


class BetterleaksParser:
    """A class that can be used to parse the Betterleaks JSON report files"""

    def get_fields(self) -> list[str]:
        return [
            "title",
            "description",
            "severity",
            "file_path",
            "line",
            "dynamic_finding",
            "static_finding",
            "nb_occurences",
        ]

    def get_dedupe_fields(self) -> list[str]:
        return [
            "title",
            "line",
            "file_path",
            "description",
        ]

    def get_scan_types(self):
        return ["Betterleaks Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Betterleaks Scan findings in JSON format."

    def get_findings(self, filename, test):
        """Converts a Betterleaks report to DefectDojo findings"""
        issues = json.load(filename)
        if issues is None:
            return []

        dupes = {}

        for issue in issues:
            if issue.get("Description") or issue.get("RuleID"):
                self.get_finding(issue, test, dupes)
            else:
                msg = "Format is not recognized for Betterleaks"
                raise ValueError(msg)

        return list(dupes.values())

    def get_finding(self, issue, test, dupes):
        reason = issue.get("Description", "Secret Leak")
        line = issue.get("StartLine")
        line = int(line) if line else 0
        match = issue.get("Match")
        secret = issue.get("Secret")
        file_path = issue.get("File")
        commit = issue.get("Commit")
        date = issue.get("Date")
        message = issue.get("Message")
        tags = issue.get("Tags")
        rule_id = issue.get("RuleID")

        title = f"Hard coded {reason} found in {file_path}"

        description = ""
        if secret:
            description += f"**Secret:** {secret}\n"
        if match:
            description += f"**Match:** {match}\n"
        if message:
            if len(message.split("\n")) > 1:
                description += (
                    "**Commit message:**\n```\n"
                    + message.replace("```", "\\`\\`\\`")
                    + "\n```\n"
                )
            else:
                description += f"**Commit message:** {message}\n"
        if commit:
            description += f"**Commit hash:** {commit}\n"
        if date:
            description += f"**Commit date:** {date}\n"
        if rule_id:
            description += f"**Rule Id:** {rule_id}\n"

        if description.endswith("\n"):
            description = description[:-1]

        severity = "High"

        dupe_key = hashlib.md5(
            (title + (secret or "") + str(line)).encode("utf-8"),
            usedforsecurity=False,
        ).hexdigest()

        if dupe_key in dupes:
            finding = dupes[dupe_key]
            finding.description = (
                finding.description + "\n\n***\n\n" + description
            )
            finding.nb_occurences += 1
            dupes[dupe_key] = finding
        else:
            finding = Finding(
                title=title,
                test=test,
                cwe=798,  # Use of Hard-coded Credentials
                description=description,
                severity=severity,
                file_path=file_path,
                line=line,
                dynamic_finding=False,
                static_finding=True,
                nb_occurences=1,
            )
            if tags:
                finding.unsaved_tags = tags
            if locations_enabled() and file_path:
                finding.unsaved_locations.append(
                    LocationData.code(file_path=file_path, line=line),
                )
            dupes[dupe_key] = finding