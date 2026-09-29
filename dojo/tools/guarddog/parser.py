import json

from dojo.models import Finding


class GuardDogParser:

    """
    Parser for GuardDog JSON reports.

    GuardDog inspects a PyPI or npm package for indicators of malicious behaviour. Its rules
    fall into two families: ``threat-*`` rules describe behaviour that is suspicious in a
    package, while ``capability-*`` rules record that the package is *able* to do something,
    which is an observation rather than an accusation.

    Where GuardDog's risk engine has correlated a rule into a scored risk, that risk carries
    an explicit severity which takes precedence over the rule family.
    """

    # GuardDog's Level enum, used for the severity of a correlated risk.
    SEVERITY = {
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }

    def get_scan_types(self):
        return ["GuardDog Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import GuardDog reports in JSON format, generated with 'guarddog pypi scan <target> --output-format json'."

    def get_findings(self, file, test):
        data = json.load(file)
        package = data.get("package")
        risk_score = data.get("risk_score") or {}
        # Risks are keyed by the rule that raised them, so a rule hit can borrow its severity.
        risks = {
            risk.get("threat_rule"): risk
            for risk in (data.get("risks") or [])
            if risk.get("threat_rule")
        }

        findings = []
        for rule_id, matches in (data.get("results") or {}).items():
            # GuardDog lists every rule it ran, with an empty result for the ones that
            # did not match.
            if not matches:
                continue
            risk = risks.get(rule_id)
            findings.extend(
                self._to_finding(rule_id, match, risk, package, risk_score, test)
                for match in matches
            )
        return findings

    def _to_finding(self, rule_id, match, risk, package, risk_score, test):
        location = match.get("location") or ""
        file_path, _, line = location.partition(":")

        description = []
        if match.get("message"):
            description.append(match["message"])
        description.append(f"**Rule:** {rule_id}")
        if package:
            description.append(f"**Package:** {package}")
        if match.get("match"):
            description.append(f"**Matched:** `{match['match']}`")
        if risk:
            if risk.get("threat_description"):
                description.append(f"**Risk:** {risk['threat_description']}")
            if risk.get("category"):
                description.append(f"**Category:** {risk['category']}")
            if risk.get("mitre_tactics"):
                description.append(f"**MITRE tactics:** {', '.join(risk['mitre_tactics'])}")
        if risk_score.get("label"):
            description.append(f"**Package risk:** {risk_score['label']} ({risk_score.get('score')})")
        if match.get("code"):
            description.append(f"**Code:**\n```\n{match['code']}\n```")

        return Finding(
            title=f"{rule_id} in {package}" if package else rule_id,
            test=test,
            description="\n".join(description),
            severity=self._severity(rule_id, risk),
            file_path=file_path or None,
            line=int(line) if line.isdigit() else None,
            component_name=package,
            vuln_id_from_tool=rule_id,
            static_finding=True,
            dynamic_finding=False,
        )

    def _severity(self, rule_id, risk):
        if risk and risk.get("severity"):
            return self.SEVERITY.get(str(risk["severity"]).lower(), "Medium")
        # A capability that the risk engine did not correlate into a scored risk is an
        # observation about what the package can do, not evidence that it does it.
        if rule_id.startswith("capability-"):
            return "Info"
        return "Medium"
