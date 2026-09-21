import json

from dojo.models import Finding


class SlitherParser:

    """
    Parser for Slither JSON reports.

    Slither is a static analyser for Solidity. Each detector result carries an *impact* and a
    *confidence*; impact is the severity axis and confidence describes how sure Slither is
    that the finding is real.
    """

    # Slither's own impact scale.
    SEVERITY = {
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Info",
        "optimization": "Info",
    }

    def get_scan_types(self):
        return ["Slither Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Slither reports in JSON format, generated with 'slither <target> --json report.json'."

    def get_findings(self, file, test):
        data = json.load(file)
        detectors = (data.get("results") or {}).get("detectors") or []
        findings = []
        for detector in detectors:
            check = detector.get("check")
            file_path, line = self._location(detector)

            description = []
            if detector.get("description"):
                description.append(detector["description"].strip())
            description.extend([
                f"**Detector:** {check}",
                f"**Impact:** {detector.get('impact')}",
                f"**Confidence:** {detector.get('confidence')}",
            ])
            if file_path:
                description.append(f"**Location:** {file_path}:{line}" if line else f"**Location:** {file_path}")

            findings.append(Finding(
                title=f"{check}: {self._summary(detector)}",
                test=test,
                description="\n".join(description),
                severity=self.SEVERITY.get(str(detector.get("impact")).lower(), "Medium"),
                file_path=file_path,
                line=line,
                vuln_id_from_tool=check,
                # Slither's id is a stable hash of the finding's content.
                unique_id_from_tool=detector.get("id"),
                references=detector.get("reference") or None,
                static_finding=True,
                dynamic_finding=False,
            ))
        return findings

    def _summary(self, detector):
        """Slither descriptions are multi-line; the first line names the affected element."""
        description = (detector.get("description") or "").strip()
        return description.split("\n")[0].strip() if description else detector.get("check")

    def _location(self, detector):
        for element in detector.get("elements") or []:
            mapping = element.get("source_mapping") or {}
            path = mapping.get("filename_relative") or mapping.get("filename_short")
            if not path:
                continue
            lines = mapping.get("lines") or []
            return path, (lines[0] if lines else None)
        return None, None
