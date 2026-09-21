import json
import re

from defusedxml import ElementTree

from dojo.models import Finding


class TerraformComplianceParser:

    """
    Parser for terraform-compliance, a BDD policy framework for Terraform plans.

    terraform-compliance has no report flag of its own. It runs on top of the radish BDD runner
    and passes unrecognised arguments straight through to it, so a machine readable report comes
    from one of radish's writers:

    - ``--junit-xml <file>`` is the one to prefer. Its failure text is terraform-compliance's own
      message, which names the offending resource, the property and the value that was found.
    - ``--cucumber-json <file>`` is also accepted, but radish records only whitespace as the
      failure message for a terraform-compliance step, so those imports say which policy failed
      without saying which resource failed it.

    Both are handled here and the format is detected from the file, so whichever a pipeline
    already produces can be imported.

    One scenario becomes one Finding. A scenario is a single policy requirement written as a
    sentence, which is the unit a team writes, reviews and remediates; its steps are the
    mechanics of checking it.
    """

    # terraform-compliance's failure sentence, for example:
    # "public_network_access_enabled property in azurerm_postgresql_server.example resource does
    #  not match with ^false$ case insensitive regex. It is set to True."
    FAILURE_DETAIL = re.compile(
        r"(?P<property>\S+) property in (?P<resource>\S+) resource (?P<verdict>.+?)(?:\Z|\.\s)",
        re.DOTALL,
    )
    FAILURE_LINE = re.compile(r"^\s*Failure:\s*(?P<message>.+)$", re.MULTILINE | re.DOTALL)

    def get_scan_types(self):
        return ["terraform-compliance Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import terraform-compliance results. Generate a report by passing a radish writer "
            "through, with 'terraform-compliance --features <dir> --planfile <plan.json> "
            "--junit-xml report.xml'. The --cucumber-json report is also accepted."
        )

    def get_findings(self, file, test):
        content = file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")

        stripped = content.strip()
        if not stripped:
            return []
        if stripped.startswith("<"):
            return self._findings_from_junit(stripped, test)
        return self._findings_from_cucumber(stripped, test)

    # ------------------------------------------------------------------ junit

    def _findings_from_junit(self, content, test):
        root = ElementTree.fromstring(content)
        findings = []
        for testcase in root.iter("testcase"):
            failures = [child for child in testcase if child.tag in {"failure", "error"}]
            if not failures:
                continue
            findings.append(self._junit_finding(testcase, failures, test))
        return findings

    def _junit_finding(self, testcase, failures, test):
        scenario = testcase.get("name") or "terraform-compliance scenario"
        feature = testcase.get("classname")
        # The failing step is the failure element's message; the body holds the whole scenario
        # plus terraform-compliance's own "Failure: ..." explanation.
        failed_step = failures[0].get("message")
        body = "\n".join(part for failure in failures for part in [failure.text or ""] if part)

        detail_match = self.FAILURE_LINE.search(body)
        detail = detail_match.group("message").strip() if detail_match else None

        resource, prop = self._resource_and_property(detail)

        description = []
        if detail:
            description.append(detail)
        description.append(f"**Scenario:** {scenario}")
        if feature:
            description.append(f"**Feature:** {feature}")
        if failed_step:
            description.append(f"**Failed step:** {failed_step.strip()}")
        if resource:
            description.append(f"**Resource:** {resource}")
        if prop:
            description.append(f"**Property:** {prop}")
        steps = self._steps_before_failure(body)
        if steps:
            description.append("**Steps:**\n" + "\n".join(f"- {step}" for step in steps))

        return self._finding(scenario, description, resource, feature, test)

    # --------------------------------------------------------------- cucumber

    def _findings_from_cucumber(self, content, test):
        data = json.loads(content)
        findings = []
        for feature in data if isinstance(data, list) else [data]:
            feature_name = feature.get("name")
            uri = feature.get("uri")
            for element in feature.get("elements") or []:
                failed = [
                    step for step in element.get("steps") or []
                    if (step.get("result") or {}).get("status") in {"failed", "error"}
                ]
                if not failed:
                    continue
                findings.append(self._cucumber_finding(element, failed, feature_name, uri, test))
        return findings

    def _cucumber_finding(self, element, failed, feature_name, uri, test):
        scenario = element.get("name") or "terraform-compliance scenario"

        description = []
        # radish records only whitespace here for a terraform-compliance step; say so rather than
        # leaving a Finding that looks like the detail was simply missing.
        messages = [
            (step.get("result") or {}).get("error_message", "").strip()
            for step in failed
        ]
        detail = next((message for message in messages if message), None)
        if detail:
            description.append(detail)
        else:
            description.append(
                "terraform-compliance did not record a failure message in the cucumber report. "
                "Re-run with --junit-xml to capture which resource and property failed.",
            )
        description.append(f"**Scenario:** {scenario}")
        if feature_name:
            description.append(f"**Feature:** {feature_name}")
        if uri:
            description.append(f"**Feature file:** {uri}")
        description.append(
            "**Failed steps:**\n"
            + "\n".join(f"- {step.get('name', '').strip()}" for step in failed),
        )
        all_steps = [step.get("name", "").strip() for step in element.get("steps") or []]
        if all_steps:
            description.append("**Steps:**\n" + "\n".join(f"- {step}" for step in all_steps))

        finding = self._finding(scenario, description, None, feature_name, test)
        finding.file_path = uri or None
        line = (failed[0] or {}).get("line")
        if line:
            finding.line = line
        return finding

    # ----------------------------------------------------------------- shared

    @staticmethod
    def _steps_before_failure(body):
        """
        List the scenario's steps, stopping at the failure explanation.

        The failure text follows the steps after a "Failure:" marker and can wrap onto further
        lines, so collecting every non-marker line would put the tail of the explanation in with
        the steps.
        """
        steps = []
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith("Failure:"):
                break
            if stripped:
                steps.append(stripped)
        return steps

    def _resource_and_property(self, detail):
        if not detail:
            return None, None
        match = self.FAILURE_DETAIL.search(detail)
        if not match:
            return None, None
        return match.group("resource"), match.group("property")

    def _finding(self, scenario, description, resource, feature, test):
        title = f"{scenario}: {resource}" if resource else scenario
        return Finding(
            title=title,
            test=test,
            description="\n".join(description),
            # terraform-compliance reports compliance, not exploitability. See the docs page.
            severity="Medium",
            component_name=resource or feature or None,
            vuln_id_from_tool=scenario,
            static_finding=True,
            dynamic_finding=False,
        )
