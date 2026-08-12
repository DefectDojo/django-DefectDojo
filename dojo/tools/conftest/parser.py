import json

from django.conf import settings

from dojo.models import Finding
from dojo.tools.locations import LocationData

# Conftest separates a policy's `deny` rules from its `warn` rules and reports them in different
# arrays, which is the only severity signal it gives. "exceptions" and "skipped" are deliberately
# not imported: an exception is a rule the policy author explicitly allowed, and a skipped policy
# was not evaluated at all - neither is a finding.
RESULT_KINDS = (
    ("failures", "High"),
    ("warnings", "Medium"),
)


class ConftestParser:

    """Parses the JSON report produced by `conftest test --output json`."""

    def get_scan_types(self):
        return ["Conftest Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Conftest Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the JSON report produced by `conftest test --output json <path>`."

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, list):
            msg = f"A Conftest JSON report is an array of checked files; got a {type(data).__name__}."
            raise TypeError(msg)

        findings = []
        for entry in data:
            if not isinstance(entry, dict):
                msg = "Every entry in a Conftest report must be an object."
                raise TypeError(msg)
            for key, severity in RESULT_KINDS:
                # A clean run omits these keys entirely rather than emitting empty arrays, so they
                # have to be fetched defensively.
                findings.extend(
                    self.build_finding(result, entry, severity, test)
                    for result in entry.get(key) or []
                )
        return findings

    def build_finding(self, result, entry, severity, test):
        file_path = entry.get("filename")
        query = (result.get("metadata") or {}).get("query")

        finding = Finding(
            test=test,
            # Rego deny and warn rules are anonymous, so the rule's own message is the only name a
            # finding has.
            title=result.get("msg") or "Conftest policy violation",
            severity=severity,
            description=self.build_description(result, entry, severity, query),
            file_path=file_path,
            # The query names the rule set the violation came from - the closest thing to a rule id
            # that Rego offers, since individual deny rules have no identifier.
            vuln_id_from_tool=query or None,
            static_finding=True,
            dynamic_finding=False,
        )
        if settings.V3_FEATURE_LOCATIONS and file_path:
            # Conftest reports the file it evaluated but never a line inside it.
            finding.unsaved_locations.append(LocationData.code(file_path=file_path))
        return finding

    def build_description(self, result, entry, severity, query):
        parts = []
        if message := result.get("msg"):
            parts.append(message)
        # Saying which array the result came from makes the severity traceable back to the policy.
        parts.append(f"**Result:** {'deny' if severity == 'High' else 'warn'}")
        if namespace := entry.get("namespace"):
            parts.append(f"**Policy namespace:** {namespace}")
        if query:
            parts.append(f"**Query:** {query}")
        if file_path := entry.get("filename"):
            parts.append(f"**File:** {file_path}")

        # A policy is free to attach anything else to metadata; keep it rather than dropping it.
        extra = {
            key: value for key, value in (result.get("metadata") or {}).items() if key != "query"
        }
        parts.extend(f"**{key}:** {value}" for key, value in sorted(extra.items()))
        return "\n".join(parts)
