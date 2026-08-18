import json

from dojo.models import Finding


class SbomqsParser:

    """
    Parser for sbomqs JSON reports.

    sbomqs scores the *quality* of an SBOM rather than looking for vulnerabilities: whether
    it carries suppliers, licences, checksums and the other elements required by NTIA and BSI
    guidance. Each feature that scores below its maximum becomes a Finding describing a gap in
    the document.
    """

    def get_scan_types(self):
        return ["sbomqs Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import sbomqs SBOM quality reports in JSON format, generated with 'sbomqs score <sbom> --json'."

    def get_findings(self, file, test):
        data = json.load(file)
        engine_version = data.get("creation_info", {}).get("scoring_engine_version")
        findings = []
        for document in data.get("files", []):
            file_name = document.get("file_name")
            for score in document.get("scores", []):
                # sbomqs marks features excluded from the run rather than dropping them.
                if score.get("ignored"):
                    continue
                value = score.get("score")
                max_score = score.get("max_score")
                if value is None or max_score is None or value >= max_score:
                    continue
                findings.append(
                    self._to_finding(score, value, max_score, document, file_name, engine_version, test),
                )
        return findings

    def _to_finding(self, score, value, max_score, document, file_name, engine_version, test):
        category = score.get("category")
        feature = score.get("feature")

        description = []
        if score.get("description"):
            description.append(score["description"])
        description.extend([
            f"**Category:** {category}",
            f"**Feature:** {feature}",
            f"**Score:** {value} of {max_score}",
        ])
        if file_name:
            description.append(f"**SBOM:** {file_name}")
        if document.get("spec"):
            description.append(f"**Spec:** {document['spec']} {document.get('spec_version', '')}".strip())
        if document.get("avg_score") is not None:
            description.append(f"**Document average score:** {round(document['avg_score'], 2)}")
        if engine_version:
            description.append(f"**Scoring engine version:** {engine_version}")

        return Finding(
            title=f"{category}: {feature}",
            test=test,
            description="\n".join(description),
            severity=self._severity(value, max_score),
            file_path=file_name,
            component_name=file_name,
            vuln_id_from_tool=feature,
            mitigation=(
                "Regenerate the SBOM with a tool that populates this element, or enrich the "
                "existing document before publishing it."
            ),
            static_finding=True,
            dynamic_finding=False,
        )

    def _severity(self, value, max_score):
        """Score each feature out of its maximum; the size of the gap sets the severity."""
        if not max_score:
            return "Info"
        ratio = value / max_score
        if ratio == 0:
            return "Medium"
        if ratio < 0.5:
            return "Low"
        return "Info"
