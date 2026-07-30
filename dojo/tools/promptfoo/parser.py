import json
import logging

from dojo.models import Finding

logger = logging.getLogger(__name__)

# promptfoo red-team severity strings -> DefectDojo severity.
SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
# Severity for a failed result that carries no red-team severity (a plain `promptfoo eval`
# assertion failure has no pluginId/severity metadata). Medium is a neutral middle rung.
DEFAULT_SEVERITY = "Medium"

# Ascending severity ranking, used only to keep the most severe rung when aggregating.
SEVERITY_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

# Starter plugin/category -> CWE mapping, matched by substring (most specific first) against
# the red-team pluginId and harmCategory. Verified against MITRE CWE 4.x:
#   CWE-89    Improper Neutralization of Special Elements used in an SQL Command
#   CWE-78    Improper Neutralization of Special Elements used in an OS Command
#   CWE-1427  Improper Neutralization of Input Used for LLM Prompting (prompt injection)
#   CWE-200   Exposure of Sensitive Information to an Unauthorized Actor (PII / data leak)
#   CWE-1426  Improper Validation of Generative AI Output (default / output safety)
# promptfoo plugin ids look like "harmful:hate", "pii:direct", "indirect-prompt-injection",
# "sql-injection". Order matters: the specific *-injection rules must precede the broad
# "injection" rule. Intentionally coarse; refine as promptfoo's plugin taxonomy is mapped
# more finely.
PLUGIN_CWE_RULES = [
    ("sql-injection", 89),
    ("shell-injection", 78),
    ("injection", 1427),
    ("prompt-extraction", 1427),
    ("pii", 200),
    ("privacy", 200),
]
DEFAULT_CWE = 1426

# promptfoo ResultFailureReason enum (src/types/index.ts): NONE=0, ASSERT=1, ERROR=2.
# A failed assertion is a finding; an ERROR is a provider/eval failure (the test could not
# run), which is operational noise rather than a vulnerability, so it is skipped.
FAILURE_REASON_ERROR = 2


class PromptfooParser:

    """
    Parser for promptfoo (https://promptfoo.dev), an LLM evaluation and red-teaming tool.

    Consumes the JSON results file written by ``promptfoo eval -o results.json`` (and
    ``promptfoo redteam run -o results.json``). promptfoo's semantics are inverted relative
    to most scanners: a result with ``success: true`` means every assertion passed -- for a
    red-team probe that means the target model defended successfully -- so it is NOT a
    finding. A result with ``success: false`` is an assertion failure (for a red-team probe,
    the attack succeeded) and becomes a Finding. Failures for the same red-team plugin against
    the same target are aggregated into one Finding. Verified against the promptfoo results
    schema (``results.version == 3``).
    """

    def get_scan_types(self):
        return ["Promptfoo Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Promptfoo Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import the JSON results file produced by `promptfoo eval -o results.json` "
            "(or `promptfoo redteam run -o results.json`). Each failed evaluation result "
            "(a failed assertion / successful red-team attack) becomes a Finding; failures "
            "for the same plugin and target are aggregated into one Finding."
        )

    def get_findings(self, file, test):
        self.dupes = {}
        if file is None:
            return []
        data = self._load(file)
        results = self._extract_results(data)
        if results is None:
            # The file parsed as JSON but did not match any promptfoo results shape. Fail
            # loudly with a hint rather than silently importing zero findings.
            msg = (
                "Unrecognized promptfoo results file: could not locate the evaluation "
                "results array (expected `results.results` from `promptfoo eval -o "
                "results.json`). Please attach the unmodified promptfoo results JSON."
            )
            raise ValueError(msg)
        share_url = data.get("shareableUrl") if isinstance(data, dict) else None
        for result in results:
            if not isinstance(result, dict):
                continue
            if result.get("success"):
                continue  # all assertions passed (model defended) -> not a finding
            if result.get("failureReason") == FAILURE_REASON_ERROR:
                continue  # provider/eval error, not a security finding
            self._process_failure(result, share_url, test)
        findings = list(self.dupes.values())
        if not findings:
            # A recognized promptfoo file with zero findings is a legitimate, common outcome:
            # every probe passed, i.e. the target defended all attacks. Log why so a
            # successful-but-empty import is explained rather than silently confusing.
            logger.info(
                "promptfoo: parsed %d result(s) and created 0 findings - every result "
                "passed (target defended all attacks) or errored; nothing to import.",
                len(results),
            )
        return findings

    def _load(self, file):
        if file is None:
            return {}
        content = file.read()
        # Uploads may arrive as bytes (binary handle) and may carry a UTF-8 BOM; utf-8-sig
        # strips it. A text handle is BOM-stripped explicitly.
        if isinstance(content, bytes):
            content = content.decode("utf-8-sig")
        elif content[:1] == "\ufeff":
            content = content[1:]
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            msg = (
                "Invalid promptfoo results file: expected the JSON produced by "
                "`promptfoo eval -o results.json` (or `promptfoo redteam run -o results.json`)."
            )
            raise ValueError(msg) from e

    def _extract_results(self, data):
        # promptfoo nests the EvaluateResult array under results.results. Accept a top-level
        # "results" list or a bare list as lenient fallbacks for hand-trimmed exports. Return
        # None (not []) when nothing matches, so the caller can tell an unrecognized file apart
        # from a valid promptfoo run that simply had no failing results.
        if isinstance(data, dict):
            results = data.get("results")
            if isinstance(results, dict) and isinstance(results.get("results"), list):
                return results["results"]
            if isinstance(results, list):
                return results
        elif isinstance(data, list):
            return data
        return None

    def _process_failure(self, result, share_url, test):
        metadata = result.get("metadata") or {}
        plugin_id = metadata.get("pluginId")
        harm_category = metadata.get("harmCategory")
        provider = self._provider_name(result.get("provider"))
        severity = self._severity(metadata.get("severity"))

        # Weakness identity for aggregation: red-team failures share a pluginId; a plain-eval
        # failure falls back to the failed assertion type. Aggregate same weakness + same target.
        weakness_id = plugin_id or self._assertion_type(result) or "assertion-failure"
        dupe_key = f"{weakness_id}::{provider}"
        if dupe_key in self.dupes:
            finding = self.dupes[dupe_key]
            finding.nb_occurences += 1
            if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(finding.severity, 0):
                finding.severity = severity
            return

        title = self._title(plugin_id, harm_category, result)
        finding = Finding(
            test=test,
            title=title,
            description=self._build_description(result, metadata),
            severity=severity,
            cwe=self._cwe(plugin_id, harm_category),
            references=share_url or None,
            component_name=provider or None,
            vuln_id_from_tool=weakness_id,
            unique_id_from_tool=dupe_key,
            static_finding=True,
            dynamic_finding=False,
            nb_occurences=1,
        )
        finding.unsaved_tags = [tag for tag in ["promptfoo", plugin_id, harm_category] if tag]
        self.dupes[dupe_key] = finding

    def _severity(self, raw):
        if isinstance(raw, str):
            return SEVERITY_MAP.get(raw.strip().lower(), DEFAULT_SEVERITY)
        return DEFAULT_SEVERITY

    def _cwe(self, plugin_id, harm_category):
        haystack = f"{plugin_id or ''} {harm_category or ''}".lower()
        for needle, cwe in PLUGIN_CWE_RULES:
            if needle in haystack:
                return cwe
        return DEFAULT_CWE

    def _title(self, plugin_id, harm_category, result):
        if plugin_id:
            title = f"{harm_category} ({plugin_id})" if harm_category else plugin_id
        else:
            assertion_type = self._assertion_type(result)
            title = f"Failed assertion: {assertion_type}" if assertion_type else "promptfoo assertion failure"
        if len(title) > 255:
            title = title[:252] + "..."
        return title

    def _provider_name(self, provider):
        if isinstance(provider, dict):
            return provider.get("label") or provider.get("id") or ""
        if isinstance(provider, str):
            return provider
        return ""

    def _assertion_type(self, result):
        components = (result.get("gradingResult") or {}).get("componentResults") or []
        failed = [c for c in components if isinstance(c, dict) and not c.get("pass")]
        # Prefer the assertion that actually failed; fall back to the first component.
        for component in failed or components:
            if isinstance(component, dict):
                assertion = component.get("assertion") or {}
                label = assertion.get("metric") or assertion.get("type")
                if label:
                    return label
        return None

    def _build_description(self, result, metadata):
        parts = []
        plugin_id = metadata.get("pluginId")
        if plugin_id:
            parts.append(f"**Plugin:** {plugin_id}")
        if metadata.get("harmCategory"):
            parts.append(f"**Harm category:** {metadata['harmCategory']}")
        if metadata.get("goal"):
            parts.append(f"**Goal:** {metadata['goal']}")
        provider = self._provider_name(result.get("provider"))
        if provider:
            parts.append(f"**Target:** {provider}")
        reason = (result.get("gradingResult") or {}).get("reason")
        if reason:
            parts.append(f"**Why it failed:** {reason}")
        prompt_text = self._prompt_text(result)
        if prompt_text:
            parts.append(f"**Attack input:**\n```\n{prompt_text}\n```")
        output_text = self._output_text(result)
        if output_text:
            parts.append(f"**Model output:**\n```\n{output_text}\n```")
        return "\n\n".join(parts)

    def _prompt_text(self, result):
        variables = result.get("vars")
        if isinstance(variables, dict) and variables:
            return "\n".join(f"{key}: {value}" for key, value in variables.items())
        if isinstance(variables, str):
            return variables
        prompt = result.get("prompt")
        if isinstance(prompt, dict):
            return prompt.get("raw") or prompt.get("label") or ""
        return ""

    def _output_text(self, result):
        response = result.get("response")
        if isinstance(response, dict):
            output = response.get("output")
            if isinstance(output, str):
                return output
            if output is not None:
                return json.dumps(output, indent=2)
        return ""
