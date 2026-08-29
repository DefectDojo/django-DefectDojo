import datetime
import html
import json
import re

from dojo.models import Endpoint, Finding
from dojo.utils import parse_cvss_data


class OPFParser:

    """
    Parser for the Open Pentest Format (OPF), a JSON format for pentest findings.

    Spec: https://cairnsecurity.com/opf
    """

    SEVERITY_MAP = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Info",
    }

    def get_scan_types(self):
        return ["OPF Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "OPF Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import an Open Pentest Format (OPF) .opf.json file. "
            "See https://cairnsecurity.com/opf."
        )

    def get_findings(self, file, test):
        data = json.load(file)
        if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
            msg = "Invalid OPF file: expected an object with a 'findings' array."
            raise TypeError(msg)

        report_date = self._parse_date((data.get("metadata") or {}).get("exportedAt"))

        findings = []
        for entry in data["findings"]:
            if not isinstance(entry, dict) or not str(entry.get("title", "")).strip():
                continue
            findings.append(self._build_finding(entry, test, report_date))
        return findings

    def _build_finding(self, entry, test, report_date):
        severity = self.SEVERITY_MAP.get(str(entry.get("severity", "")).lower(), "Info")

        description = self._html_to_text(entry.get("description", "")) or entry["title"]

        # Only URL assets become endpoints. Source paths, ARNs and the like go
        # in the description instead.
        url_assets, other_assets = self._split_assets(entry.get("affectedAssets"))
        if other_assets:
            description = description + "\n\nAffected assets:\n" + "\n".join(f"- {a}" for a in other_assets)

        finding = Finding(
            title=str(entry["title"])[:511],
            test=test,
            severity=severity,
            description=description,
            static_finding=False,
            dynamic_finding=True,
        )

        if report_date:
            finding.date = report_date

        cwe = self._first_cwe(entry)
        if cwe is not None:
            finding.cwe = cwe

        # OPF cvssVector is not pinned to a CVSS version, so let DefectDojo detect
        # v4/v3/v2 and route each to its own field with an authoritative score
        # rather than storing the vector raw in cvssv3.
        vector = entry.get("cvssVector")
        cvss = parse_cvss_data(vector) if isinstance(vector, str) and vector else {}
        if cvss.get("cvssv3"):
            finding.cvssv3 = cvss["cvssv3"]
            if cvss.get("cvssv3_score") is not None:
                finding.cvssv3_score = cvss["cvssv3_score"]
        if cvss.get("cvssv4"):
            finding.cvssv4 = cvss["cvssv4"]
            if cvss.get("cvssv4_score") is not None:
                finding.cvssv4_score = cvss["cvssv4_score"]
        # Fall back to the tool-reported score only when the vector yielded none
        # (no vector, an unparseable one, or a v2 vector with no v3/v4 field to hold it).
        if finding.cvssv3_score is None and finding.cvssv4_score is None:
            score = entry.get("cvssScore")
            if isinstance(score, (int, float)):
                finding.cvssv3_score = float(score)

        impact = self._html_to_text(entry.get("impact", ""))
        if impact:
            finding.impact = impact
        mitigation = self._html_to_text(entry.get("recommendation", ""))
        if mitigation:
            finding.mitigation = mitigation

        steps = entry.get("stepsToReproduce")
        if isinstance(steps, list) and steps:
            finding.steps_to_reproduce = "\n".join(
                f"{i}. {self._html_to_text(str(step))}" for i, step in enumerate(steps, start=1)
            )

        references = entry.get("references")
        if isinstance(references, list) and references:
            lines = []
            for ref in references:
                if isinstance(ref, dict) and ref.get("url"):
                    title = ref.get("title")
                    lines.append(f"{title}: {ref['url']}" if title else str(ref["url"]))
            if lines:
                finding.references = "\n".join(lines)

        cve_ids = entry.get("cveIds")
        if isinstance(cve_ids, list) and cve_ids:
            finding.unsaved_vulnerability_ids = [str(cve) for cve in cve_ids]

        opf_id = entry.get("id")
        if opf_id:
            finding.unique_id_from_tool = str(opf_id)
            finding.vuln_id_from_tool = str(opf_id)

        if url_assets:
            finding.unsaved_endpoints = url_assets

        tags = []
        if entry.get("testType"):
            tags.append(str(entry["testType"]))
        if entry.get("owaspCategory"):
            tags.append(str(entry["owaspCategory"]))
        tags.extend(str(technique) for technique in entry.get("mitreTechniques") or [])
        if tags:
            finding.unsaved_tags = tags

        return finding

    @staticmethod
    def _split_assets(assets):
        if not isinstance(assets, list):
            return [], []
        endpoints, other = [], []
        for asset in assets:
            if not isinstance(asset, str) or not asset.strip():
                continue
            value = asset.strip()
            if "://" not in value:
                other.append(value)
                continue
            try:
                endpoints.append(Endpoint.from_uri(value))
            except Exception:
                # Not a parseable URL after all; keep it in the description.
                other.append(value)
        return endpoints, other

    @staticmethod
    def _first_cwe(entry):
        candidates = list(entry.get("cweIds") or [])
        if entry.get("cweId"):
            candidates.append(entry["cweId"])
        for value in candidates:
            match = re.search(r"(\d+)", str(value))
            if match:
                return int(match.group(1))
        return None

    @staticmethod
    def _parse_date(value):
        if not isinstance(value, str):
            return None
        match = re.match(r"(\d{4})-(\d{2})-(\d{2})", value)
        if not match:
            return None
        try:
            return datetime.date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
        except ValueError:
            return None

    @staticmethod
    def _html_to_text(value):
        if not value or not isinstance(value, str):
            return ""
        text = re.sub(r"<br\s*/?>", "\n", value, flags=re.IGNORECASE)
        text = re.sub(r"</(p|div|li|h[1-6]|tr)>", "\n", text, flags=re.IGNORECASE)
        text = re.sub(r"<li[^>]*>", "- ", text, flags=re.IGNORECASE)
        text = re.sub(r"<[^>]+>", "", text)
        # Decode the full named + numeric HTML entity set rather than a partial
        # hand-rolled map, so entities like &apos; &#x27; &#8217; do not leak through.
        text = html.unescape(text)
        return re.sub(r"\n{3,}", "\n\n", text).strip()
