"""Parse Xygeni SAST reports into DefectDojo Findings."""

from dojo.models import Finding
from dojo.tools.xygeni._common import map_severity, parse_cwe


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

    finding = Finding(
        test=test,
        title=str(vuln.get("detector") or "Xygeni SAST finding"),
        description="\n\n".join(description_parts) if description_parts else "",
        severity=map_severity(vuln.get("severity")),
        file_path=file_path,
        line=line,
        cwe=parse_cwe(cwes=vuln.get("cwes"), cwe=vuln.get("cwe"), tags=vuln.get("tags")),
        static_finding=True,
        dynamic_finding=False,
        # One detector can flag the same code pattern at several locations. Xygeni reuses a
        # single ``uniqueHash`` across those occurrences but gives each a distinct ``issueId``
        # (which encodes filepath + line). Dedup is keyed on ``unique_id_from_tool``, so use
        # the per-occurrence ``issueId`` to keep each occurrence as its own Finding;
        # ``uniqueHash`` groups them as the vuln id.
        unique_id_from_tool=vuln.get("issueId") or vuln.get("uniqueHash"),
        vuln_id_from_tool=vuln.get("uniqueHash"),
    )

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
