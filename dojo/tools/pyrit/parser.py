import json

from dojo.models import Finding


class PyRITParser:

    """
    Parser for PyRIT, Microsoft's Python Risk Identification Tool for generative AI.

    PyRIT runs attacks against a generative AI target and records an ``AttackResult`` per attack:
    the objective it was pursuing, how many turns it took, the outcome, and the score the last
    response was given. A JSON array of those results, or an object with a ``results`` or
    ``attack_results`` list, is accepted.

    Only attacks that got somewhere become Findings. An attack whose outcome is ``failure`` is the
    target's guardrails doing their job, in the same way a passing policy check is not a finding,
    so it is not imported.
    """

    OUTCOME_SUCCESS = "success"
    OUTCOME_FAILURE = "failure"
    OUTCOME_ERROR = "error"
    OUTCOME_UNDETERMINED = "undetermined"

    # pyrit/models/results/attack_result.py defines these four outcomes. Severity follows what
    # each one says about the target, not how bad the objective sounds.
    SEVERITY_BY_OUTCOME = {
        OUTCOME_SUCCESS: "High",
        OUTCOME_UNDETERMINED: "Low",
        OUTCOME_ERROR: "Info",
    }

    def get_scan_types(self):
        return ["PyRIT Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import PyRIT attack results in JSON format, exported from a PyRIT memory store."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for result in self._iter_results(data):
            outcome = (result.get("outcome") or self.OUTCOME_UNDETERMINED).lower()
            if outcome == self.OUTCOME_FAILURE:
                continue
            findings.append(self._to_finding(result, outcome, test))
        return findings

    def _iter_results(self, data):
        if isinstance(data, list):
            candidates = data
        elif isinstance(data, dict):
            candidates = data.get("results") or data.get("attack_results") or []
        else:
            candidates = []
        for candidate in candidates:
            if isinstance(candidate, dict):
                yield candidate

    def _to_finding(self, result, outcome, test):
        objective = result.get("objective") or "unspecified objective"
        strategy = self._strategy_name(result)
        harms = [harm for harm in result.get("targeted_harm_categories") or [] if harm]

        title = f"{strategy}: {objective}" if strategy else objective

        description = [f"**Objective:** {objective}", f"**Outcome:** {outcome}"]
        if result.get("outcome_reason"):
            description.append(f"**Outcome reason:** {result['outcome_reason']}")
        if strategy:
            description.append(f"**Attack strategy:** {strategy}")
        if harms:
            description.append(f"**Targeted harm categories:** {', '.join(harms)}")
        if result.get("executed_turns") is not None:
            description.append(f"**Turns executed:** {result['executed_turns']}")
        if result.get("conversation_id"):
            description.append(f"**Conversation id:** {result['conversation_id']}")
        if result.get("attack_result_id"):
            description.append(f"**Attack result id:** {result['attack_result_id']}")

        score = result.get("last_score") or {}
        if score:
            for key, label in (
                ("score_type", "Score type"),
                ("score_value", "Score value"),
                ("score_category", "Score category"),
                ("score_rationale", "Score rationale"),
            ):
                if score.get(key) not in {None, ""}:
                    description.append(f"**{label}:** {score[key]}")

        if outcome == self.OUTCOME_ERROR:
            description.append(
                "PyRIT recorded an infrastructure error rather than a refusal, so this attack "
                "did not complete and the target's behaviour was not established.",
            )
            for key, label in (("error_type", "Error type"), ("error_message", "Error message")):
                if result.get(key):
                    description.append(f"**{label}:** {result[key]}")

        last_response = result.get("last_response") or {}
        if last_response.get("original_value"):
            description.append(
                f"**Last response:**\n```\n{last_response['original_value']}\n```",
            )

        finding = Finding(
            title=title,
            test=test,
            description="\n".join(description),
            severity=self.SEVERITY_BY_OUTCOME.get(outcome, "Low"),
            component_name=strategy or None,
            vuln_id_from_tool=strategy or None,
            static_finding=False,
            dynamic_finding=True,
        )
        finding.unsaved_tags = [f"pyrit-outcome-{outcome}", *[str(harm) for harm in harms]]
        return finding

    @staticmethod
    def _strategy_name(result):
        identifier = result.get("atomic_attack_identifier") or {}
        if isinstance(identifier, dict):
            return identifier.get("name") or identifier.get("__type__") or None
        return None
