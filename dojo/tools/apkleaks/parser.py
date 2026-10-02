import json

from dojo.models import Finding

# APKLeaks grades nothing - there is no severity, confidence or CWE anywhere in its output, and its
# pattern set is user-extensible, so a per-rule ranking shipped here would be guesswork that goes
# stale the moment someone adds a pattern. Everything imports at one level and the docs page says to
# triage by rule name, which is the finding title.
DEFAULT_SEVERITY = "Medium"


class ApkleaksParser:

    """Parses the JSON report produced by `apkleaks --json`."""

    def get_scan_types(self):
        return ["APKLeaks Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "APKLeaks Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the JSON report produced by `apkleaks -f <app.apk> --json -o report.json`."

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, dict):
            msg = f"An APKLeaks report is a JSON object; got a {type(data).__name__}."
            raise TypeError(msg)

        package = data.get("package")
        findings = []
        for result in data.get("results") or []:
            if not isinstance(result, dict):
                msg = "Every result in an APKLeaks report must be an object."
                raise TypeError(msg)
            findings.append(self.build_finding(result, package, test))
        return findings

    def build_finding(self, result, package, test):
        name = result.get("name") or "APKLeaks pattern"
        matches = [match for match in result.get("matches") or [] if match]

        # One finding per PATTERN, not per match. APKLeaks reports no file or line - a match is just
        # the matched string - so per-match findings would differ only by that string, which puts
        # secret material into finding titles and produces a finding per URL for the link patterns.
        # The actionable unit is "this package leaks a Google API key"; the matches are its evidence
        # and their count is nb_occurences.
        return Finding(
            test=test,
            title=f"{name} found in {package}" if package else str(name),
            severity=DEFAULT_SEVERITY,
            description=self.build_description(name, package, matches),
            component_name=package or None,
            static_finding=True,
            dynamic_finding=False,
            vuln_id_from_tool=str(name),
            nb_occurences=len(matches) or 1,
        )

    def build_description(self, name, package, matches):
        parts = [f"**Pattern:** {name}"]
        if package:
            parts.append(f"**Package:** {package}")
        parts.append(f"**Matches:** {len(matches)}")
        if matches:
            body = "\n".join(matches)
            parts.append(f"```\n{body}\n```")
        return "\n".join(parts)
