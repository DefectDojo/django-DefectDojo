"""Parse Xygeni SAST reports into DefectDojo Findings."""

from dojo.models import Finding
from dojo.tools.xygeni._common import map_severity, parse_cwes


def parse_sast(data, test):
    """Convert a Xygeni SAST JSON report into a list of Findings."""
    return [_build_finding(vuln, test) for vuln in data.get("vulnerabilities") or []]


def _build_finding(vuln, test):
    location = vuln.get("location") or {}
    file_path = location.get("filepath")
    line = location.get("beginLine")
    code = location.get("code")

    description_parts = []
    if vuln.get("explanation"):
        description_parts.append(str(vuln["explanation"]))
    if code:
        description_parts.append(f"```\n{code}\n```")

    code_flow_text = _render_code_flows(vuln.get("codeFlows") or [])
    if code_flow_text:
        description_parts.append(code_flow_text)

    primary_cwe, all_cwes = parse_cwes(
        cwes=vuln.get("cwes"), cwe=vuln.get("cwe"), tags=vuln.get("tags"),
    )

    finding = Finding(
        test=test,
        title=str(vuln.get("detector") or "Xygeni SAST finding"),
        description="\n\n".join(description_parts) if description_parts else "",
        severity=map_severity(vuln.get("severity")),
        file_path=file_path,
        line=line,
        cwe=primary_cwe,
        static_finding=True,
        dynamic_finding=False,
        # ``uniqueHash`` is Xygeni's identity for a finding across scans. For SAST it is
        # MD5(kind + detector + filepath + normalized code), with the line deliberately excluded:
        # two findings on the same line with different code get different hashes (kept distinct),
        # while the same code that shifts lines keeps its identity (no churn). ``detector`` is the
        # rule that fired, used as the non-unique grouping id.
        unique_id_from_tool=vuln.get("uniqueHash"),
        vuln_id_from_tool=vuln.get("detector"),
    )

    if all_cwes:
        finding.unsaved_cwes = all_cwes

    _apply_code_flow_fields(finding, vuln.get("codeFlows") or [])
    return finding


def _render_code_flows(code_flows):
    """Render Xygeni codeFlows[] into a human-readable markdown block for Finding.description."""
    if not code_flows:
        return ""

    flow = code_flows[0]
    lines = ["**Data flow**"]
    for frame in flow.get("frames") or []:
        kind = frame.get("kind") or "step"
        loc = frame.get("location") or {}
        filepath = loc.get("filepath", "?")
        line = loc.get("beginLine", "?")
        snippet = (loc.get("code") or "").strip()
        lines.append(f"- **{kind}** {filepath}:{line} — `{snippet}`")
    return "\n".join(lines) if len(lines) > 1 else ""


def _apply_code_flow_fields(finding, code_flows):
    """Populate Finding.sast_source_* / sast_sink_object from the first code flow's first source/sink."""
    if not code_flows:
        return
    frames = code_flows[0].get("frames") or []
    source = next((f for f in frames if f.get("kind") == "source"), None)
    sink = next((f for f in frames if f.get("kind") == "sink"), None)

    if source:
        loc = source.get("location") or {}
        finding.sast_source_file_path = loc.get("filepath")
        finding.sast_source_line = loc.get("beginLine")
        if source.get("injectionPoint"):
            finding.sast_source_object = source["injectionPoint"]

    if sink:
        finding.sast_sink_object = sink.get("injectionPoint") or (sink.get("location") or {}).get("code")
