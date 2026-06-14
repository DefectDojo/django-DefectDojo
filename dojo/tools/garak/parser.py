import json
import logging

from dojo.models import Finding

logger = logging.getLogger(__name__)

# Ordered (ascending) severity ladder used by this parser. Index positions drive the
# probe-family adjustment (a "+1"/"-1" nudge) on top of the score-derived base severity.
# This is the parser's own ranking and is deliberately independent of the reverse-ordered
# Finding.SEVERITIES mapping in dojo.models.
SEVERITY_LADDER = ["Info", "Low", "Medium", "High", "Critical"]

# Probe families whose hits warrant nudging severity UP one rung: active attack,
# code-execution, or jailbreak intent.
SEVERITY_UP_FAMILIES = {
    "dan",
    "promptinject",
    "latentinjection",
    "exploitation",
    "malwaregen",
    "xss",
}

# Probe families whose hits warrant nudging severity DOWN one rung: content/quality
# issues that usually carry lower direct risk than an exploit.
SEVERITY_DOWN_FAMILIES = {
    "misleading",
    "snowball",
    "continuation",
    "toxicity",
}

# Starter probe-family -> CWE mapping. Verified against MITRE CWE 4.x:
#   CWE-1427  Improper Neutralization of Input Used for LLM Prompting (prompt injection)
#   CWE-1426  Improper Validation of Generative AI Output (default / output safety)
#   CWE-79    Improper Neutralization of Input During Web Page Generation (XSS)
#   CWE-200   Exposure of Sensitive Information to an Unauthorized Actor
# Intentionally coarse; refine as garak's probe taxonomy is mapped more finely.
PROBE_FAMILY_CWE = {
    "promptinject": 1427,
    "dan": 1427,
    "latentinjection": 1427,
    "goodside": 1427,
    "xss": 79,
    "leakreplay": 200,
    "divergence": 200,
}
DEFAULT_CWE = 1426

# Fallback score for a hit record that carries no numeric score. Every line in a
# garak hit log is, by construction, a detector hit, so an unscored hit is treated
# as a strong hit rather than benign.
DEFAULT_HIT_SCORE = 1.0


class GarakParser:

    """
    Parser for garak (https://github.com/NVIDIA/garak), NVIDIA's LLM vulnerability scanner.

    Consumes the JSON Lines hit log (``garak.<run_id>.hitlog.jsonl``) produced by a garak
    run. Every line in a hit log is, by construction, a detector hit, so each record maps to
    (or aggregates into) a DefectDojo Finding. Verified against the garak 0.15.x hit-log
    schema defined in garak/evaluators/base.py.
    """

    def get_scan_types(self):
        return ["Garak Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Garak Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import the JSON Lines hit log (garak.<run_id>.hitlog.jsonl) produced by garak, "
            "NVIDIA's LLM vulnerability scanner. Each detector hit becomes a Finding; hits for "
            "the same probe, target, and detector are aggregated into one Finding."
        )

    def get_findings(self, file, test):
        self.dupes = {}
        if file is None:
            return []
        logger.debug("Garak parser: reading hit log %s", getattr(file, "name", file))
        for raw_line in file:
            # Decode with utf-8-sig and strip any leading BOM so a hit log re-saved by a
            # BOM-adding editor (common on Windows) does not break json parsing of line 1.
            line = raw_line.decode("utf-8-sig") if isinstance(raw_line, bytes) else raw_line
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                msg = (
                    "Invalid Garak hit log: expected JSON Lines (one JSON hit record per "
                    "line). Provide the garak.<run_id>.hitlog.jsonl file produced by garak."
                )
                raise ValueError(msg) from e
            if isinstance(record, dict) and record.get("probe"):
                self._process_hit(record, test)
        return list(self.dupes.values())

    def _process_hit(self, record, test):
        probe = record.get("probe", "")
        detector = record.get("detector", "")
        generator = record.get("generator", "")
        goal = record.get("goal", "")
        probe_family = probe.split(".")[0] if probe else ""
        detector_family = detector.split(".")[0] if detector else ""
        severity = self._severity(record.get("score"), probe_family)

        # Aggregate every hit of the same probe against the same target via the same detector
        # into one Finding: bump the occurrence count and escalate to the most severe rung seen.
        # The description/prompt/output are taken from the first hit; only severity is escalated.
        dupe_key = f"{probe}::{generator}::{detector}"
        if dupe_key in self.dupes:
            finding = self.dupes[dupe_key]
            finding.nb_occurences += 1
            if SEVERITY_LADDER.index(severity) > SEVERITY_LADDER.index(finding.severity):
                finding.severity = severity
            return

        title = f"{probe}: {goal}".strip().rstrip(":").strip()
        if len(title) > 255:
            title = title[:252] + "..."

        finding = Finding(
            test=test,
            title=title,
            description=self._build_description(record),
            severity=severity,
            cwe=PROBE_FAMILY_CWE.get(probe_family, DEFAULT_CWE),
            references=self._reference(probe_family),
            component_name=generator or None,
            vuln_id_from_tool=probe,
            unique_id_from_tool=dupe_key,
            static_finding=True,
            dynamic_finding=False,
            nb_occurences=1,
        )
        finding.unsaved_tags = [tag for tag in ["garak", probe_family, detector_family] if tag]
        self.dupes[dupe_key] = finding

    def _severity(self, score, probe_family):
        try:
            score_val = float(score)
        except (TypeError, ValueError):
            score_val = DEFAULT_HIT_SCORE
        if score_val >= 0.9:
            base = 3  # High
        elif score_val >= 0.7:
            base = 2  # Medium
        elif score_val >= 0.4:
            base = 1  # Low
        else:
            base = 0  # Info
        if probe_family in SEVERITY_UP_FAMILIES:
            base += 1
        elif probe_family in SEVERITY_DOWN_FAMILIES:
            base -= 1
        base = max(0, min(base, len(SEVERITY_LADDER) - 1))
        return SEVERITY_LADDER[base]

    def _reference(self, probe_family):
        if not probe_family:
            return "https://reference.garak.ai/en/latest/probes.html"
        return f"https://reference.garak.ai/en/latest/garak.probes.{probe_family}.html"

    def _build_description(self, record):
        goal = record.get("goal")
        probe = record.get("probe")
        detector = record.get("detector")
        score = record.get("score")
        generator = record.get("generator")
        triggers = record.get("triggers")
        prompt_text = self._message_text(record.get("prompt"))
        output_text = self._message_text(record.get("output"))

        parts = []
        if goal:
            parts.append(f"**Goal:** {goal}")
        if probe:
            parts.append(f"**Probe:** {probe}")
        if detector:
            parts.append(f"**Detector:** {detector}")
        if score is not None:
            parts.append(f"**Detector score:** {score}")
        if generator:
            parts.append(f"**Target:** {generator}")
        if prompt_text:
            parts.append(f"**Prompt:**\n```\n{prompt_text}\n```")
        if output_text:
            parts.append(f"**Model output:**\n```\n{output_text}\n```")
        if triggers:
            parts.append(f"**Triggers:**\n```json\n{json.dumps(triggers, indent=2)}\n```")
        return "\n\n".join(parts)

    def _message_text(self, obj):
        """
        Extract human-readable text from a garak prompt or output value.

        garak serialises a prompt as a Conversation (via dataclasses.asdict) ->
        {"turns": [{"role": ..., "content": {"text": ...}}], "notes": {}} and an output as a
        single Message -> {"text": ...}. Older or looser payloads may carry a plain string.
        All three shapes are handled.
        """
        if obj is None:
            return ""
        if isinstance(obj, str):
            return obj
        if isinstance(obj, dict):
            if obj.get("text") is not None:
                return str(obj["text"])
            turns = obj.get("turns")
            if isinstance(turns, list):
                lines = []
                for turn in turns:
                    if not isinstance(turn, dict):
                        continue
                    content = turn.get("content")
                    role = turn.get("role") or ""
                    text = ""
                    if isinstance(content, dict):
                        text = content.get("text") or ""
                    elif isinstance(content, str):
                        text = content
                    if text:
                        lines.append(f"{role}: {text}" if role else text)
                return "\n".join(lines)
        return ""
