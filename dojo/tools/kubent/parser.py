import json
import re

from dojo.models import Finding

# kubent names its rulesets after the release the APIs are removed in, e.g.
# "Deprecated APIs removed in 1.16".
REMOVED_IN = re.compile(r"removed in ([0-9]+\.[0-9]+)", re.IGNORECASE)


class KubentParser:

    """
    Parser for kube-no-trouble (kubent) JSON reports.

    kubent reports only the objects it found using a deprecated API version, so every item in
    a report is a finding. It attaches no severity and does not distinguish an API that is
    merely deprecated from one already removed.
    """

    def get_scan_types(self):
        return ["kubent Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import kube-no-trouble (kubent) reports in JSON format, generated with 'kubent -o json'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for item in data or []:
            kind = item.get("Kind")
            name = item.get("Name")
            api_version = item.get("ApiVersion")
            replacement = item.get("ReplaceWith")
            ruleset = item.get("RuleSet")

            description = [
                f"**Object:** {kind}/{name}",
                f"**API version:** {api_version}",
            ]
            if item.get("Namespace"):
                description.insert(1, f"**Namespace:** {item['Namespace']}")
            if ruleset:
                description.append(f"**Ruleset:** {ruleset}")
            removed_in = self._removed_in(ruleset)
            if removed_in:
                description.append(f"**Removed in Kubernetes:** {removed_in}")
            if item.get("Since"):
                description.append(f"**Deprecated since:** {item['Since']}")
            if replacement:
                description.append(f"**Replacement API:** {replacement}")

            findings.append(Finding(
                title=f"Deprecated API {api_version} used by {kind}/{name}",
                test=test,
                description="\n".join(description),
                # kubent grades nothing: every item it emits is a deprecated API usage.
                severity="Medium",
                mitigation=(
                    f"Migrate {kind}/{name} from {api_version} to {replacement}."
                    if replacement
                    else f"Move {kind}/{name} off the {api_version} API."
                ),
                component_name=f"{kind}/{name}",
                component_version=api_version,
                vuln_id_from_tool=f"{api_version}/{kind}",
                static_finding=True,
                dynamic_finding=False,
            ))
        return findings

    def _removed_in(self, ruleset):
        if not ruleset:
            return None
        match = REMOVED_IN.search(ruleset)
        return match.group(1) if match else None
