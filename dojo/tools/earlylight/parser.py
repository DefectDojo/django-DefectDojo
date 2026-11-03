"""
Parser for Early Light JSON reports.

Early Light (https://github.com/DefectDojo/earlylight) is DefectDojo's open source
emerging-vulnerability scanner: one detector per vulnerability, run against
filesystems, container images, source trees and live hosts. This parser reads
the report written by ``earlylight scan <fs|image|repo|host> --format json``.

Verdicts:

- ``vulnerable``: imported, tagged ``earlylight``.
- ``unknown``: imported, tagged ``earlylight`` and ``needs-review``; the reason
  Early Light could not settle it is in the description.
- ``fixed``, ``inactive`` and ``managed``: cleared by Early Light, not imported.
"""

import hashlib
import json

from dojo.models import Finding

SCAN_TYPE = "Early Light Scan"

TAG = "earlylight"
NEEDS_REVIEW_TAG = "needs-review"

IMPORTED_VERDICTS = {"vulnerable", "unknown"}

# Severity a finding states for itself (php2shell sets one; "review" and "none"
# are not severities and fall through to the table below).
FINDING_SEVERITIES = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
}

# Severity and CWE of each "<detector>/<kind>", taken from the detector manifests
# (`earlylight detectors --format json`). Reports from Early Light releases after
# v0.3.1 list each detector's kinds with their score and level, and those win;
# this table covers older reports and supplies the CWE. The kind's CVSS-style
# "severity" score maps to >=9 Critical, >=7 High, >=4 Medium, else Low. Kinds
# without a score use their SARIF level: error is High, warning is Medium, note
# is Info. The CWE is the first one the kind lists.
KIND_SEVERITY = {
    # brotli: CVE-2026-111497
    "brotli/decoder-library": ("Critical", 252),  # 9.2
    "brotli/bundled-decoder": ("Critical", 252),  # 9.2
    "brotli/go-port": ("Medium", 252),  # 5.3
    "brotli/node-pin": ("Critical", 252),  # 9.2
    "brotli/dotnet-pin": ("Critical", 252),  # 9.2
    "brotli/bun-pin": ("Critical", 252),  # 9.2
    "brotli/dependency": ("Critical", 252),  # 9.2
    "brotli/not-checked": ("Info", None),  # level note
    # emudhra: CVE-2026-111943 (trust kinds carry no CVE of their own)
    "emudhra/compromised-key": ("High", None),  # level error
    "emudhra/path-root": ("High", None),  # level error
    "emudhra/weak-key": ("High", None),  # level error
    "emudhra/unpatched-go": ("Medium", None),  # level warning
    "emudhra/issued-by-compromised-ca": ("High", None),  # level error
    # php2shell: CVE-2026-109618, CVE-2026-109619
    "php2shell/php-runtime-web": ("Critical", 416),  # 9.2
    "php2shell/php-runtime-cli": ("High", 416),  # 7.5
    "php2shell/php-image": ("Critical", 416),  # 9.2
}

LEVEL_SEVERITY = {"error": "High", "warning": "Medium", "note": "Info"}

# Kinds neither the report nor this table describe.
UNKNOWN_KIND_SEVERITY = {"vulnerable": "High", "unknown": "Medium"}

# Facts that tell two findings of one kind at one path apart (two certificates
# in one bundle, two images in one file).
IDENTITY_FACTS = ("spki_sha256", "cert_sha256", "image")

TITLE_MAX = 500


class EarlylightParser:

    """Early Light JSON report (``earlylight scan ... --format json``)."""

    def get_scan_types(self):
        return [SCAN_TYPE]

    def get_label_for_scan_types(self, scan_type):
        return SCAN_TYPE

    def get_description_for_scan_types(self, scan_type):
        return (
            "Early Light emerging-vulnerability scanner JSON report. Generate it with "
            "'earlylight scan <fs|image|repo|host> --format json ...'. Vulnerable findings are imported, "
            "unknown ones are imported tagged needs-review, and findings Early Light cleared are skipped."
        )

    def get_findings(self, file, test):
        content = file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        try:
            data = json.loads(content)
        except ValueError as e:
            msg = f"Invalid Early Light JSON report: {e}"
            raise ValueError(msg) from e
        if not isinstance(data, dict) or not isinstance(data.get("targets"), list):
            msg = "Invalid Early Light JSON report: expected an object with a 'targets' list"
            # ValueError, not TypeError: the importer turns ValueError into a validation error for the user
            raise ValueError(msg)  # noqa: TRY004

        detectors = {d.get("id"): d for d in data.get("detectors") or [] if isinstance(d, dict)}
        findings = []
        seen = {}
        for target in data["targets"]:
            if not isinstance(target, dict):
                continue
            for item in target.get("findings") or []:
                if not isinstance(item, dict) or item.get("verdict") not in IMPORTED_VERDICTS:
                    continue
                finding = self._build_finding(item, target, detectors.get(item.get("detector")) or {}, test)
                finding.unique_id_from_tool = self._unique_id(item, target, seen)
                findings.append(finding)
        return findings

    def _build_finding(self, item, target, detector, test):
        detector_id = item.get("detector") or ""
        kind = item.get("kind") or ""
        rule = f"{detector_id}/{kind}"
        verdict = item["verdict"]
        facts = item.get("facts") or {}
        path = item.get("path") or None
        message = item.get("message") or ""
        known_severity, cwe = KIND_SEVERITY.get(rule, (None, None))
        known_severity = self._reported_kind_severity(detector, kind) or known_severity

        title = f"{rule}: {message}" if message else rule
        if len(title) > TITLE_MAX:
            title = title[: TITLE_MAX - 3] + "..."

        is_host = target.get("type") == "host"
        finding = Finding(
            test=test,
            title=title,
            severity=self._severity(item, known_severity),
            description=self._description(item, target, detector),
            mitigation=item.get("fix") or None,
            references="\n".join(detector.get("advisories") or []) or None,
            file_path=path,
            static_finding=not is_host,
            dynamic_finding=is_host,
            vuln_id_from_tool=rule,
        )
        if cwe:
            finding.cwe = cwe
        line = item.get("line")
        if isinstance(line, int) and line > 0:
            finding.line = line
        if item.get("fix"):
            finding.fix_available = True
        component_name, component_version = self._component(facts)
        if component_name:
            finding.component_name = component_name
        if component_version:
            finding.component_version = component_version

        # Only the finding's own CVEs, never the detector's list: an eMudhra trust
        # finding has no CVE even though the detector names one.
        cves = []
        for cve in item.get("cves") or []:
            cve_id = cve.get("id") if isinstance(cve, dict) else None
            if cve_id and cve_id not in cves:
                cves.append(cve_id)
        if cves:
            finding.unsaved_vulnerability_ids = cves

        finding.unsaved_tags = [TAG, NEEDS_REVIEW_TAG] if verdict == "unknown" else [TAG]
        return finding

    def _severity(self, item, known_severity):
        stated = FINDING_SEVERITIES.get(str(item.get("severity") or "").lower())
        if stated:
            return stated
        if known_severity:
            return known_severity
        return UNKNOWN_KIND_SEVERITY[item["verdict"]]

    def _reported_kind_severity(self, detector, kind):
        for k in detector.get("kinds") or []:
            if not isinstance(k, dict) or k.get("id") != kind:
                continue
            try:
                score = float(k.get("severity") or "")
            except ValueError:
                return LEVEL_SEVERITY.get(k.get("level"))
            if score >= 9:
                return "Critical"
            if score >= 7:
                return "High"
            if score >= 4:
                return "Medium"
            return "Low"
        return None

    def _component(self, facts):
        if facts.get("product"):
            # brotli: the program or library carrying the decoder
            return facts["product"], facts.get("version")
        if facts.get("ecosystem") and facts.get("package"):
            # brotli: a dependency that bundles the decoder
            return facts["package"], facts.get("current")
        if facts.get("package"):
            # php2shell: the OS package that installed PHP, "name version"
            name, _, version = facts["package"].partition(" ")
            return name, version or None
        if facts.get("php_version"):
            return "php", facts["php_version"]
        return None, None

    def _description(self, item, target, detector):
        verdict = item["verdict"]
        lines = []
        if verdict == "unknown":
            lines.extend([
                "**Needs review:** Early Light could not settle this finding.",
                f"**Reason:** {item.get('reason') or 'not given'}",
            ])
        else:
            lines.append("**Verdict:** vulnerable")
            if item.get("reason"):
                lines.append(f"**Reason:** {item['reason']}")
        if item.get("message"):
            lines.append(f"**Message:** {item['message']}")

        target_parts = [target.get("type"), target.get("digest"), target.get("platform")]
        target_details = ", ".join(p for p in target_parts if p)
        target_line = f"**Target:** {target.get('target') or ''}"
        if target_details:
            target_line += f" ({target_details})"
        lines.append(target_line)

        if item.get("path"):
            where = item["path"]
            if isinstance(item.get("line"), int) and item["line"] > 0:
                where += f":{item['line']}"
            lines.append(f"**Path:** {where}")
        if item.get("method"):
            lines.append(f"**Method:** {item['method']}")

        detector_line = f"**Detector:** {item.get('detector')}/{item.get('kind')}"
        if detector.get("title"):
            detector_line += f" ({detector['title']})"
        lines.append(detector_line)

        facts = item.get("facts") or {}
        if facts:
            lines.extend(["", "**Facts:**"])
            lines.extend(f"- {key}: {facts[key]}" for key in sorted(facts))

        cves = [c for c in item.get("cves") or [] if isinstance(c, dict) and c.get("id")]
        if cves:
            lines.extend(["", "**CVE verdicts:**"])
            for cve in cves:
                cve_line = f"- {cve['id']}: {cve.get('verdict') or 'unknown'}"
                if cve.get("reason"):
                    cve_line += f" ({cve['reason']})"
                lines.append(cve_line)
        return "\n".join(lines)

    def _unique_id(self, item, target, seen):
        # Stable across runs: no line numbers or wording. Identical findings in one
        # report are told apart by their order, as the SARIF fingerprint does.
        facts = item.get("facts") or {}
        parts = [
            f"{item.get('detector')}/{item.get('kind')}",
            str(target.get("type") or ""),
            str(target.get("target") or ""),
            str(item.get("path") or ""),
        ]
        parts.extend(f"{key}={facts[key]}" for key in IDENTITY_FACTS if facts.get(key))
        key = "\x00".join(parts)
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            key += f"\x00{seen[key]}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()
