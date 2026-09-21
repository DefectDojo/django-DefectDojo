import json

from dojo.models import Finding


class CloudsplainingParser:

    """
    Parser for Cloudsplaining JSON results.

    Cloudsplaining assesses AWS IAM policies and sorts the risky actions it finds into its own
    risk categories. A single permissive policy can contain thousands of flagged actions --
    ``PowerUserAccess`` alone yields over three thousand -- so a Finding is raised per policy
    and risk category, with the actions listed in the description, rather than per action.
    """

    # Cloudsplaining's own risk categories. Its CLI treats resource exposure, privilege
    # escalation and data exfiltration as the high priority ones (--high-priority-only).
    SEVERITY = {
        "PrivilegeEscalation": "Critical",
        "DataExfiltration": "High",
        "ResourceExposure": "High",
        "CredentialsExposure": "High",
        "ServiceWildcard": "Medium",
        "InfrastructureModification": "Low",
    }

    # The sections of the report that hold policies. IAM principals reference these by id.
    POLICY_SECTIONS = (
        "customer_managed_policies",
        "inline_policies",
        "aws_managed_policies",
    )

    def get_scan_types(self):
        return ["Cloudsplaining Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Cloudsplaining IAM results in JSON format, generated with 'cloudsplaining scan --input-file account.json'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for section in self.POLICY_SECTIONS:
            for policy in (data.get(section) or {}).values():
                # Cloudsplaining keeps excluded policies in the results, flagged rather than
                # removed, so that the exclusion is auditable.
                if policy.get("is_excluded"):
                    continue
                findings.extend(self._policy_findings(policy, section, test))
        return findings

    def _policy_findings(self, policy, section, test):
        policy_name = policy.get("PolicyName")
        findings = []
        for category, severity in self.SEVERITY.items():
            actions = policy.get(category) or []
            if not actions:
                continue

            description = [
                f"**Policy:** {policy_name}",
                f"**Risk:** {category}",
                f"**Policy type:** {section}",
                f"**Flagged actions ({len(actions)}):**",
                "\n".join(f"- {action}" for action in actions),
            ]
            if policy.get("Arn"):
                description.insert(1, f"**ARN:** {policy['Arn']}")

            findings.append(Finding(
                title=f"{category}: {policy_name}",
                test=test,
                description="\n".join(description),
                severity=severity,
                component_name=policy_name,
                vuln_id_from_tool=category,
                mitigation=(
                    "Restrict the policy to the actions and resource ARNs the principal "
                    "actually needs, or add an exclusion if the access is intended."
                ),
                static_finding=True,
                dynamic_finding=False,
            ))
        return findings
