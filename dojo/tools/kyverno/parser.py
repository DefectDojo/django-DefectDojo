import json

from dojo.models import Finding


class KyvernoParser:

    """
    Parser for Kyverno policy reports.

    Kyverno reports results against Kubernetes resources as a report object holding a
    ``results`` list. Two API groups are in circulation and both are accepted here: the original
    ``wgpolicyk8s.io`` PolicyReport and ClusterPolicyReport, and the newer ``openreports.io``
    Report and ClusterReport that current Kyverno releases emit. The results themselves have the
    same shape in both, so the report kind only decides where to look.

    A Kubernetes List wrapping several reports is also accepted, since that is what
    ``kubectl get policyreport -A -o json`` produces.
    """

    # Kyverno results carry the severity the policy author declared through the
    # policies.kyverno.io/severity annotation. These are the values that annotation accepts.
    SEVERITY = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }

    # Fallback when the policy declared no severity: derive it from the outcome instead.
    SEVERITY_BY_RESULT = {
        "fail": "Medium",
        "warn": "Low",
        "error": "High",
    }

    # pass and skip are not findings: the resource satisfied the policy, or the rule did not
    # apply to it. error means Kyverno could not evaluate the rule, which is worth knowing.
    REPORTABLE_RESULTS = frozenset({"fail", "warn", "error"})

    def get_scan_types(self):
        return ["Kyverno Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import Kyverno policy reports in JSON format, generated with "
            "'kyverno apply <policy> --resource <resource> --policy-report --output-format json' "
            "or exported from a cluster with 'kubectl get policyreport -o json'."
        )

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for report in self._iter_reports(data):
            for result in report.get("results") or []:
                if (result.get("result") or "").lower() not in self.REPORTABLE_RESULTS:
                    continue
                findings.extend(self._to_findings(result, test))
        return findings

    def _iter_reports(self, data):
        """Yield each report, whether the file holds one report or a List of them."""
        if not isinstance(data, dict):
            return
        if isinstance(data.get("items"), list):
            for item in data["items"]:
                if isinstance(item, dict):
                    yield item
            return
        yield data

    def _to_findings(self, result, test):
        """
        One Finding per resource the result names.

        A single Kyverno result can reference several resources when a policy is evaluated in
        bulk, and each of those is a separate thing to fix, so they do not share a Finding.
        """
        resources = result.get("resources") or [{}]
        return [self._to_finding(result, resource, test) for resource in resources]

    def _to_finding(self, result, resource, test):
        policy = result.get("policy") or ""
        rule = result.get("rule") or ""
        outcome = (result.get("result") or "").lower()
        declared_severity = (result.get("severity") or "").lower()

        resource_name = self._resource_name(resource)
        title = f"{policy}/{rule}" if rule else policy
        if resource_name:
            title = f"{title}: {resource_name}"

        description = []
        if result.get("message"):
            description.append(result["message"])
        description.append(f"**Policy:** {policy}")
        if rule:
            description.append(f"**Rule:** {rule}")
        description.append(f"**Result:** {outcome}")
        if result.get("category"):
            description.append(f"**Category:** {result['category']}")
        if declared_severity:
            description.append(f"**Policy severity:** {declared_severity}")
        else:
            description.append(
                "**Policy severity:** not declared, so severity was derived from the result",
            )
        if resource_name:
            description.append(f"**Resource:** {resource_name}")
        if resource.get("apiVersion"):
            description.append(f"**API version:** {resource['apiVersion']}")
        if result.get("source"):
            description.append(f"**Source:** {result['source']}")
        if result.get("scored") is not None:
            description.append(f"**Scored:** {result['scored']}")
        for key, value in (result.get("properties") or {}).items():
            description.append(f"**{key}:** {value}")

        return Finding(
            title=title,
            test=test,
            description="\n".join(description),
            severity=self._severity(declared_severity, outcome),
            component_name=resource_name or None,
            vuln_id_from_tool=f"{policy}/{rule}" if rule else policy or None,
            static_finding=True,
            dynamic_finding=False,
        )

    def _severity(self, declared_severity, outcome):
        if declared_severity in self.SEVERITY:
            return self.SEVERITY[declared_severity]
        return self.SEVERITY_BY_RESULT.get(outcome, "Medium")

    @staticmethod
    def _resource_name(resource):
        """Render a resource as kind/namespace/name, skipping the parts that are absent."""
        kind = resource.get("kind")
        namespace = resource.get("namespace")
        name = resource.get("name")
        if not name:
            return None
        parts = [part for part in (kind, namespace, name) if part]
        return "/".join(parts)
