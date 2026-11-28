import json
import logging
import math

from dojo.models import Finding
from dojo.utils import parse_cvss_data

logger = logging.getLogger(__name__)

SEVERITIES = {"Low", "Medium", "High", "Critical"}

# Used when the vector string does not belong to the newest scored CVSS version. The NVD database that
# kirkstone/scarthgap cve-check reads keeps the CVSS v2 vector whenever one exists, so an old CVE with
# both scores carries a v2 vector next to a v3 score. CVSS v2 has no Critical band.
CVSS_V3_V4_BANDS = ((9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"))
CVSS_V2_BANDS = ((7.0, "High"), (4.0, "Medium"), (0.1, "Low"))

# Yocto files a CVE as Ignored for reasons that mean "this image is not affected" (not-applicable-config,
# cpe-incorrect, disputed, ...). Those findings are closed as mitigated: it is the one closed state that
# reimport reopens if a later build reports the CVE as Unpatched again (false_p and out_of_scope are never
# reopened by reimport). upstream-wontfix is the exception: the vulnerable code is present and will not be
# fixed upstream, so the finding stays active.
IGNORED_BUT_VULNERABLE = {"upstream-wontfix"}


class YoctoCveCheckParser:

    """Yocto/OpenEmbedded cve-check JSON manifest, also written by sbom-cve-check (yocto-cve-check-manifest)."""

    def get_scan_types(self):
        return ["Yocto CVE Check"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import the JSON manifest from the Yocto Project cve-check class or the sbom-cve-check "
            "yocto-cve-check-manifest export. Unpatched CVEs become active findings, Ignored CVEs are "
            "closed as mitigated, and Patched CVEs are skipped."
        )

    def get_findings(self, file, test):
        content = file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8-sig")
        report = json.loads(content.removeprefix("﻿"))
        if not isinstance(report, dict) or not isinstance(report.get("package"), list):
            msg = "Invalid Yocto cve-check report: expected a JSON object with a 'package' list."
            raise ValueError(msg)  # noqa: TRY004 - parsers signal bad input with ValueError
        if not report["package"]:
            logger.info("Yocto cve-check report contains no packages")

        findings = []
        for package in report["package"]:
            issues = package.get("issue") if isinstance(package, dict) else None
            if not isinstance(package, dict) or not isinstance(issues or [], list):
                msg = "Invalid Yocto cve-check report: each package must be an object with an 'issue' list."
                raise ValueError(msg)  # noqa: TRY004 - parsers signal bad input with ValueError
            for issue in issues or []:
                if not isinstance(issue, dict) or not issue.get("id"):
                    msg = "Invalid Yocto cve-check report: each issue must be an object with an 'id'."
                    raise ValueError(msg)
                # sbom-cve-check writes null when the VEX status is unknown; cve-check can write "Unknown".
                # Anything that is not Patched or Ignored is treated as still vulnerable.
                status = self._text(issue.get("status")).strip().lower()
                if status == "patched":
                    continue
                findings.append(self._build_finding(package, issue, status, test))
        return findings

    def _build_finding(self, package, issue, status, test):
        cve_id = self._text(issue["id"]).strip()
        name = self._text(package.get("name"))[:500]
        version = self._text(package.get("version"))[:100]

        title = f"{cve_id} in {name}:{version}"
        if len(title) > 500:
            title = title[:497] + "..."

        scores = {
            4: self._score(issue.get("scorev4")),
            3: self._score(issue.get("scorev3")),
            2: self._score(issue.get("scorev2")),
        }
        vector = issue.get("vectorString")
        cvss_data = parse_cvss_data(vector) if isinstance(vector, str) else {}

        detail = self._text(issue.get("detail")).strip().lower()
        closed = status == "ignored" and detail not in IGNORED_BUT_VULNERABLE

        finding = Finding(
            test=test,
            title=title,
            severity=self._severity(scores, cvss_data),
            description=self._description(package, issue),
            references=self._text(issue.get("link")) or None,
            component_name=name,
            component_version=version,
            vuln_id_from_tool=cve_id,
            cvssv3_score=scores[3],
            cvssv4_score=scores[4],
            active=not closed,
            is_mitigated=closed,
            static_finding=True,
            dynamic_finding=False,
        )
        if closed:
            finding.mitigation = self._ignored_reason(issue)
        finding.unsaved_vulnerability_ids = [cve_id]
        if cvss_data.get("cvssv3"):
            finding.cvssv3 = cvss_data["cvssv3"]
        if cvss_data.get("cvssv4"):
            finding.cvssv4 = cvss_data["cvssv4"]
        return finding

    def _text(self, value):
        return "" if value is None else str(value)

    def _score(self, value):
        try:
            score = float(value)
        except (TypeError, ValueError):
            return None
        # Yocto writes "0.0" when there is no score for a CVSS version
        return score if math.isfinite(score) and 0 < score <= 10 else None

    def _severity(self, scores, cvss_data):
        newest = next((version for version in (4, 3, 2) if scores[version] is not None), None)
        vector_severity = cvss_data.get("severity")
        # Trust the vector only when it is for the newest scored version, or when there are no scores at all
        if vector_severity in SEVERITIES and (newest is None or cvss_data.get("major_version") == newest):
            return vector_severity
        if newest is None:
            return "Info"
        bands = CVSS_V2_BANDS if newest == 2 else CVSS_V3_V4_BANDS
        return next(severity for threshold, severity in bands if scores[newest] >= threshold)

    def _ignored_reason(self, issue):
        detail = self._text(issue.get("detail")).strip()
        reason = self._text(issue.get("description")).strip()
        text = "Yocto reports this CVE as Ignored"
        if detail:
            text += f" ({detail})"
        return f"{text}: {reason}" if reason else f"{text}."

    def _cell(self, value):
        # Keep each value on one table row: a pipe or newline would break the markdown table
        return " ".join(self._text(value).split()).replace("|", "\\|")

    def _description(self, package, issue):
        products = package.get("products")
        products = ", ".join(
            f"{p.get('product')} (CVEs in record: {p.get('cvesInRecord')})" if isinstance(p, dict) else self._text(p)
            for p in (products if isinstance(products, list) else [])
        )
        cpes = package.get("cpes")
        rows = [
            ("Package", package.get("name")),
            ("Version", package.get("version")),
            ("Layer", package.get("layer")),
            ("Products", products),
            ("Status", issue.get("status")),
            ("Status detail", issue.get("detail")),
            ("Status description", issue.get("description")),
            ("CVSS v2 score", issue.get("scorev2")),
            ("CVSS v3 score", issue.get("scorev3")),
            ("CVSS v4 score", issue.get("scorev4")),
            ("Attack vector", issue.get("vector")),
            ("Vector string", issue.get("vectorString")),
            ("NVD last modified", issue.get("modified")),
            ("CPEs", ", ".join(self._text(c) for c in cpes) if isinstance(cpes, list) else cpes),
        ]
        table = "| Field | Value |\n|---|---|\n" + "".join(
            f"| **{label}** | {self._cell(value)} |\n"
            for label, value in rows
            if self._cell(value) not in {"", "0.0", "UNKNOWN"}
        )
        summary = self._text(issue.get("summary")).strip() or "No summary available."
        return f"{summary}\n\n{table}"
