import json

from dojo.models import Finding


class FicklingParser:

    """
    Parser for Fickling safety-check JSON reports.

    Fickling statically analyses a Python pickle and returns a single verdict for the file,
    plus the individual observations that led to it. Each observation becomes a Finding
    carrying the file's verdict, so a single malicious pickle does not collapse into one
    undifferentiated result.

    Fickling's JSON does not record which file was analysed, so no file path is set. Import
    one report per pickle if you need to tell them apart.
    """

    # Fickling's own verdict scale, from fickling.analysis.
    SEVERITY = {
        "OVERTLY_MALICIOUS": "Critical",
        "LIKELY_OVERTLY_MALICIOUS": "Critical",
        "LIKELY_UNSAFE": "High",
        "SUSPICIOUS": "Medium",
        "LIKELY_SAFE": "Info",
    }

    def get_scan_types(self):
        return ["Fickling Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Fickling reports in JSON format, generated with 'fickling --check-safety --json-output report.json <pickle>'."

    def get_findings(self, file, test):
        data = json.load(file)
        verdict = str(data.get("severity") or "").upper()
        severity = self.SEVERITY.get(verdict, "Medium")
        # A pickle Fickling considers safe has nothing to report.
        if verdict == "LIKELY_SAFE":
            return []

        analysis = data.get("analysis")
        results = (data.get("detailed_results") or {}).get("AnalysisResult") or {}

        findings = []
        for check, detail in results.items():
            description = [f"**Check:** {check}"]
            if detail:
                description.append(f"**Detail:** {detail}")
            description.append(f"**Verdict:** {verdict}")
            if analysis:
                description.append(f"**Analysis:**\n{analysis}")

            findings.append(Finding(
                title=f"{check}: {verdict}",
                test=test,
                description="\n".join(description),
                severity=severity,
                vuln_id_from_tool=check,
                mitigation=(
                    "Do not unpickle this file. Obtain the model from a trusted source, or "
                    "re-serialize it in a format that cannot carry executable code."
                ),
                static_finding=True,
                dynamic_finding=False,
            ))

        # Fickling can return a verdict with no itemised results; keep the verdict visible.
        if not findings:
            findings.append(Finding(
                title=f"Pickle flagged as {verdict}",
                test=test,
                description=f"**Verdict:** {verdict}\n**Analysis:**\n{analysis or 'No detail reported.'}",
                severity=severity,
                vuln_id_from_tool=verdict,
                static_finding=True,
                dynamic_finding=False,
            ))
        return findings
