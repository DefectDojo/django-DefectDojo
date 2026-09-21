import json

from dojo.models import Finding


class PythonTaintParser:

    """
    Parser for Python Taint (pyt) JSON reports.

    Python Taint performs taint tracking: it follows untrusted input from a source to a
    dangerous sink, which is a stronger signal than a pattern match. Every reported flow is a
    tainted path reaching a sink, so findings import as High.
    """

    def get_scan_types(self):
        return ["Python Taint Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Python Taint (pyt) reports in JSON format, generated with 'pyt -j <target>'."

    def get_findings(self, file, test):
        data = json.load(file)
        return [self._to_finding(vulnerability, test) for vulnerability in data.get("vulnerabilities", [])]

    def _to_finding(self, vulnerability, test):
        source = vulnerability.get("source") or {}
        sink = vulnerability.get("sink") or {}
        source_word = vulnerability.get("source_trigger_word")
        sink_word = vulnerability.get("sink_trigger_word")
        path = source.get("path") or sink.get("path")
        source_line = source.get("line_number")
        sink_line = sink.get("line_number")

        description = [
            f"Untrusted input reaches a dangerous sink via `{source_word}` → `{sink_word}`.",
            f"**Source:** {path}:{source_line} — {source.get('label')}",
            f"**Sink:** {path}:{sink_line} — {sink.get('label')}",
        ]
        reassignments = vulnerability.get("reassignment_nodes") or []
        if reassignments:
            trace = "\n".join(
                f"- {node.get('label')} ({path}:{node.get('line_number')})"
                for node in reassignments
                if isinstance(node, dict)
            )
            if trace:
                description.append(f"**Propagation:**\n{trace}")

        # pyt keys a flow by its source/sink trigger words when it has no named rule.
        flow_id = vulnerability.get("rule") or f"{source_word} -> {sink_word}"

        return Finding(
            title=f"Tainted flow: {source_word} to {sink_word}",
            test=test,
            description="\n".join(description),
            # A completed taint flow to a sink is an exploitable path, not a hint.
            severity="High",
            file_path=path,
            # The sink is where the dangerous operation happens.
            line=sink_line,
            vuln_id_from_tool=flow_id,
            static_finding=True,
            dynamic_finding=False,
        )
