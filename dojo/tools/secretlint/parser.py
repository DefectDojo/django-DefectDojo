import hashlib
import json

from dojo.location.feature import locations_enabled
from dojo.models import Finding
from dojo.tools.locations import LocationData

# secretlint's own severity vocabulary is info | warning | error. Everything the recommended
# preset ships reports "error"; the other two are mapped so a custom rule set still imports.
SEVERITIES = {
    "error": "High",
    "warning": "Medium",
    "info": "Info",
}
DEFAULT_SEVERITY = "High"

# CWE-798: Use of Hard-coded Credentials. The same value the Gitleaks and Detect-secrets parsers
# use, so secret findings stay comparable across tools.
HARD_CODED_CREDENTIALS_CWE = 798

RULE_NAME_PREFIX = "secretlint-rule-"

# A detection is reported as type "message". Secretlint also has filter rules - the recommended
# preset ships one, which is how `secretlint-disable` comments work - and those describe ranges to
# ignore rather than secrets that were found. Filtered detections are absent from the JSON report
# today, but only detections are ever a finding, so anything else is skipped rather than imported
# as a secret named after the filter.
DETECTION_TYPE = "message"


def short_rule_name(rule_id):
    """
    Reduce "@secretlint/secretlint-rule-aws" to "aws" so titles read well.

    Third-party rules are not obliged to follow that naming, so anything that does not reduce
    cleanly is returned unchanged rather than mangled.
    """
    name = rule_id.rsplit("/", 1)[-1]
    name = name.removeprefix(RULE_NAME_PREFIX)
    return name or rule_id


class SecretlintParser:

    """Parses the JSON report produced by `secretlint --format json`."""

    def get_scan_types(self):
        return ["Secretlint Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Secretlint Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            'Import the JSON report produced by `secretlint --format json "**/*" > report.json`. '
            "Secret values are masked by secretlint itself unless it was run with "
            "`--no-maskSecrets`."
        )

    def get_findings(self, filename, test):
        data = json.load(filename)
        # secretlint reports an empty result as [], and a scanned-but-clean file as an entry
        # whose "messages" list is empty. Both mean no findings.
        if data is None:
            return []
        if not isinstance(data, list):
            msg = f"Secretlint reports are a JSON array of scanned files; got a {type(data).__name__}."
            raise TypeError(msg)

        dupes = {}
        for entry in data:
            if not isinstance(entry, dict):
                msg = "Every entry in a Secretlint report must be an object."
                raise TypeError(msg)
            file_path = entry.get("filePath")
            for message in entry.get("messages") or []:
                if message.get("type", DETECTION_TYPE) != DETECTION_TYPE:
                    continue
                self.add_finding(message, file_path, test, dupes)
        return list(dupes.values())

    def add_finding(self, message, file_path, test, dupes):
        rule_id = message.get("ruleId") or ""
        message_id = message.get("messageId") or ""
        rule = short_rule_name(rule_id) if rule_id else ""

        # A messageId is scoped to its rule, so both are needed to name the defect uniquely.
        vuln_id_from_tool = "/".join(part for part in (rule, message_id) if part) or None

        location = message.get("loc") or {}
        start = location.get("start") or {}
        line = start.get("line")
        column = start.get("column")

        # The title carries the file's base name rather than the full path: secretlint always
        # reports an absolute path, and a title tied to one checkout location reads badly and
        # changes for no reason when the same repository is scanned somewhere else.
        subject = message_id or rule or "secret"
        title = f"Hard coded {subject} found"
        if file_path:
            title += f" in {file_path.rsplit('/', 1)[-1]}"

        description = self.build_description(message, file_path, line, column, rule_id, message_id)

        finding = Finding(
            title=title,
            test=test,
            cwe=HARD_CODED_CREDENTIALS_CWE,
            description=description,
            severity=SEVERITIES.get(message.get("severity"), DEFAULT_SEVERITY),
            file_path=file_path,
            line=line,
            vuln_id_from_tool=vuln_id_from_tool,
            static_finding=True,
            dynamic_finding=False,
            nb_occurences=1,
        )
        if locations_enabled() and file_path:
            finding.unsaved_locations.append(
                LocationData.code(file_path=file_path, line=line),
            )

        dupe_key = hashlib.sha256(
            f"{rule_id}|{message_id}|{file_path}|{line}".encode(),
        ).hexdigest()
        if dupe_key in dupes:
            dupes[dupe_key].nb_occurences += 1
        else:
            dupes[dupe_key] = finding

    def build_description(self, message, file_path, line, column, rule_id, message_id):
        """
        Describe the detection without reproducing the scanned file.

        A secretlint report embeds the entire content of every scanned file under
        "sourceContent", including the secret itself in the clear. None of that is copied into
        the finding: importing a report would otherwise republish the source of every scanned
        file into DefectDojo. Only the rule's own message is used, which secretlint masks by
        default.
        """
        parts = []
        if text := message.get("message"):
            parts.append(f"**Detected:** {text}")
        if rule_id:
            parts.append(f"**Rule:** {rule_id}")
        if message_id:
            parts.append(f"**Message ID:** {message_id}")
        if parent := message.get("ruleParentId"):
            parts.append(f"**Rule preset:** {parent}")
        if file_path:
            parts.append(f"**File:** {file_path}")
        if line is not None:
            # secretlint's columns are zero-based; the line numbers are one-based.
            location = str(line) if column is None else f"{line}, column {column}"
            parts.append(f"**Line:** {location}")
        if docs_url := message.get("docsUrl"):
            parts.append(f"**Rule documentation:** {docs_url}")
        return "\n".join(parts)
