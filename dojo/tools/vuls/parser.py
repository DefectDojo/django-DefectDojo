import contextlib
import json

from dojo.models import Finding


class VulsParser:

    """
    Parser for Vuls, the agentless Linux vulnerability scanner.

    ``vuls report -format-json`` writes one ScanResult per scanned host. ``scannedCves`` maps a
    CVE id to a VulnInfo holding the packages it affects and the CVE detail Vuls gathered from
    each of its sources (NVD, the distribution's own tracker, JVN and others) under
    ``cveContents``.

    One Finding is created per affected package rather than per CVE: a CVE in three packages is
    three things to upgrade, and DefectDojo tracks the component on the Finding. A CVE with no
    package attributed to it still produces one Finding so it is not lost.
    """

    # Vuls reports CVSS scores from each source it consulted; severity follows the CVSS bands
    # rather than any judgement of its own.
    def get_scan_types(self):
        return ["Vuls Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Vuls reports in JSON format, generated with 'vuls report -format-json'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for result in data if isinstance(data, list) else [data]:
            if not isinstance(result, dict):
                continue
            server = result.get("serverName")
            platform = " ".join(part for part in (result.get("family"), result.get("release")) if part)
            for cve_id, vuln in (result.get("scannedCves") or {}).items():
                findings.extend(self._cve_findings(cve_id, vuln, server, platform, test))
        return findings

    def _cve_findings(self, cve_id, vuln, server, platform, test):
        contents = self._flatten_contents(vuln.get("cveContents") or {})
        score, score_kind, severity_word = self._best_score(contents)
        packages = vuln.get("affectedPackages") or []
        if not packages:
            packages = [{}]
        return [
            self._to_finding(cve_id, vuln, package, contents, score, score_kind, severity_word, server, platform, test)
            for package in packages
        ]

    @staticmethod
    def _flatten_contents(cve_contents):
        """CveContents maps a source name to either one CveContent or a list of them."""
        flattened = []
        for value in cve_contents.values():
            if isinstance(value, list):
                flattened.extend(item for item in value if isinstance(item, dict))
            elif isinstance(value, dict):
                flattened.append(value)
        return flattened

    @staticmethod
    def _best_score(contents):
        """
        Take the highest score Vuls found, preferring newer CVSS versions at equal score.

        Vuls reports one CveContent per source, and they disagree. Using the highest is the
        conservative reading and matches how Vuls itself sorts a report.
        """
        best = (0.0, None, None)
        for content in contents:
            for field, kind in (
                ("cvss40Score", "CVSS 4.0"),
                ("cvss3Score", "CVSS 3.x"),
                ("cvss2Score", "CVSS 2.0"),
            ):
                score = content.get(field)
                if not isinstance(score, (int, float)) or score <= 0:
                    continue
                if score > best[0]:
                    severity_field = field.replace("Score", "Severity")
                    best = (float(score), kind, content.get(severity_field))
        return best

    @staticmethod
    def _severity_from_score(score):
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        if score > 0:
            return "Low"
        return "Info"

    def _to_finding(self, cve_id, vuln, package, contents, score, score_kind, severity_word, server, platform, test):
        titles = [content.get("title") for content in contents if content.get("title")]
        summaries = [content.get("summary") for content in contents if content.get("summary")]
        headline = titles[0] if titles else cve_id

        description = []
        if summaries:
            description.append(summaries[0])
        description.append(f"**CVE:** {cve_id}")
        if server:
            description.append(f"**Server:** {server}")
        if platform:
            description.append(f"**Platform:** {platform}")
        if package.get("name"):
            description.append(f"**Package:** {package['name']}")
        if package.get("fixedIn"):
            description.append(f"**Fixed in:** {package['fixedIn']}")
        if package.get("fixState"):
            description.append(f"**Fix state:** {package['fixState']}")
        if package.get("notFixedYet") is not None:
            description.append(f"**Not fixed yet:** {package['notFixedYet']}")
        if score:
            description.append(f"**Highest score:** {score} ({score_kind})")
        if severity_word:
            description.append(f"**Reported severity:** {severity_word}")
        confidences = [
            c.get("detectionMethod") for c in vuln.get("confidences") or [] if c.get("detectionMethod")
        ]
        if confidences:
            description.append(f"**Detected by:** {', '.join(confidences)}")
        if vuln.get("kevs"):
            description.append("**Known exploited:** listed in a KEV catalogue")
        exploit_count = len(vuln.get("exploits") or []) + len(vuln.get("metasploits") or [])
        if exploit_count:
            description.append(f"**Public exploits known:** {exploit_count}")
        sources = [content.get("sourceLink") for content in contents if content.get("sourceLink")]
        if sources:
            description.append(f"**Source:** {sources[0]}")

        mitigation = "\n".join(
            f"- {m['url']}" for m in vuln.get("mitigations") or [] if isinstance(m, dict) and m.get("url")
        )

        finding = Finding(
            title=f"{cve_id}: {headline}" if headline != cve_id else cve_id,
            test=test,
            description="\n".join(description),
            severity=self._severity_from_score(score),
            component_name=package.get("name") or None,
            component_version=package.get("version") or None,
            mitigation=mitigation or None,
            cvssv3=self._first_vector(contents),
            cvssv3_score=score if score and score_kind == "CVSS 3.x" else None,
            vuln_id_from_tool=cve_id,
            static_finding=True,
            dynamic_finding=False,
        )
        finding.unsaved_vulnerability_ids = [cve_id]
        cwes = [
            cwe for content in contents for cwe in content.get("cweIDs") or []
            if isinstance(cwe, str) and cwe.upper().startswith("CWE-")
        ]
        if cwes:
            with contextlib.suppress(IndexError, ValueError):
                finding.cwe = int(cwes[0].split("-", 1)[1])
        return finding

    @staticmethod
    def _first_vector(contents):
        for content in contents:
            vector = content.get("cvss3Vector")
            if vector:
                return vector
        return None
