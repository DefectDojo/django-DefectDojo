import json
from contextlib import suppress
from datetime import datetime

from dojo.models import Finding

# The issue "type" FOSSA reports for security vulnerabilities; every other value is a licensing or
# quality issue.
TYPE_VULNERABILITY = "vulnerability"

# CVSS v3 band floors, used only when FOSSA reports "unknown" (or no) severity.
CVSS_CRITICAL_FLOOR = 9.0
CVSS_HIGH_FLOOR = 7.0
CVSS_MEDIUM_FLOOR = 4.0

# Grades FOSSA's licensing and quality issue types, none of which carry a severity field. FOSSA
# publishes no severity for these, so this table is the connector's: a policy conflict is a denial
# (High), a flag is advisory (Medium), unlicensed code is a compliance risk (Medium), a denylisted
# dependency is High, and the remaining quality signals are Low.
#
# Both spellings of the risk_* types are mapped, because FOSSA's docs table uses hyphens
# (risk_empty-package) while fossa-cli's wire format uses underscores.
LICENSING_SEVERITY_BY_TYPE = {
    "policy_conflict": "High",
    "policy_flag": "Medium",
    "unlicensed_dependency": "Medium",
    "unlicensed_and_public": "Medium",
    "blacklisted_dependency": "High",
    "outdated_dependency": "Low",
    "risk_abandonware": "Low",
    "risk_empty_package": "Low",
    "risk_empty-package": "Low",
    "risk_native_code": "Low",
    "risk_native-code": "Low",
}

VULNERABILITY_SEVERITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


class FossaParser:

    """
    Parses a FOSSA v2 issues export.

    Mirrors pkg/tools/fossa/converter field for field so a file import and an API sync deduplicate
    against each other instead of producing two copies of everything.

    FOSSA is an SCA and licence-compliance tool: an issue hangs off a dependency, never a file and
    line, so the dependency coordinates are the only location a finding has. One issue can affect
    several projects at once, and the connector makes that one finding per project - see
    unique_id_from_tool in get_fields().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanType().
        return ["FOSSA - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "FOSSA - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a FOSSA v2 issues export (JSON). Matches the scan type used by the FOSSA "
            "connector so file and API findings deduplicate. Covers both FOSSA's security "
            "vulnerabilities and its licensing and quality issues."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the FOSSA Parser.

        Mirrors the connector's IssueToFinding:
        - title: for a vulnerability "<CVE or vulnId> - <package> (<version>)"; for a licensing
          issue "<type> - <license> in <package>". Both degrade as the converter's do.
        - severity: FOSSA's own for a vulnerability, falling back to the CVSS v3 bands when FOSSA
          says "unknown"; the LICENSING_SEVERITY_BY_TYPE table otherwise.
        - description: FOSSA's advisory text, then the dependency coordinates and version ranges.
        - mitigation / references / cvssv3 / cvssv3_score / cwe: vulnerabilities only.
        - component_name / component_version: the affected dependency's name and version.
        - unique_id_from_tool: "<issue id>:<project locator>". The suffix matters - one FOSSA issue
          can affect several projects, becoming one finding per DefectDojo product, and those
          findings must not share a tool id.
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "references",
            "date",
            "cvssv3",
            "cvssv3_score",
            "cwe",
            "component_name",
            "component_version",
            "unique_id_from_tool",
            "tags",
            "active",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the FOSSA Parser.

        Copied from the FOSSA block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. Diverging would stop file findings
        merging with API-synced ones.
        """
        return ["title", "severity", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        issues = self.extract_issues(data)

        findings = {}
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            for locator in self.locators(issue):
                finding = self.build_finding(issue, locator, test)
                findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract_issues(self, data):
        """FOSSA's getIssues response wraps the list under "issues"; a bare array is accepted too."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("issues"), list):
            return data["issues"]
        msg = (
            "A FOSSA export is a JSON object with an 'issues' list, or a bare array of issues; got "
            f"{type(data).__name__}."
        )
        raise TypeError(msg)

    def locators(self, issue):
        """
        Return the project locators this issue should produce a finding for.

        The connector converts an issue once per project it syncs, suffixing the tool id with that
        project's locator. An export carries the same locators under the issue's own "projects", so
        one finding per project reproduces the connector exactly. An export with no project context
        cannot reproduce that suffix, so the tool id is the issue id alone.
        """
        projects = issue.get("projects")
        if isinstance(projects, list):
            found = [p["id"] for p in projects if isinstance(p, dict) and p.get("id")]
            if found:
                return found
        return [None]

    def build_finding(self, issue, locator, test):
        source = issue.get("source") or {}
        issue_id = issue.get("id")
        component = source.get("name") or ""
        version = source.get("version") or ""

        finding = Finding(
            test=test,
            severity=self.severity(issue),
            date=self.date(issue.get("createdAt")),
            component_name=component or None,
            component_version=version or None,
            unique_id_from_tool=f"{issue_id}:{locator}" if locator else str(issue_id),
            active=True,
            # FOSSA reads a dependency graph, never a running service.
            static_finding=True,
            dynamic_finding=False,
        )
        finding.unsaved_tags = self.tags(issue)

        if self.is_vulnerability(issue):
            self.apply_vulnerability_fields(finding, issue, component, version)
        else:
            finding.title = self.licensing_title(issue, component)
            finding.description = self.licensing_description(issue)
        return finding

    def apply_vulnerability_fields(self, finding, issue, component, version):
        """Fill in the fields that exist only on FOSSA's vulnerability issues."""
        finding.title = self.vulnerability_title(issue, component, version)
        finding.description = self.vulnerability_description(issue)
        finding.mitigation = self.mitigation(issue) or None
        finding.references = self.references(issue) or None
        finding.cvssv3_score = issue.get("cvss") or None
        finding.cvssv3 = issue.get("cvssVector") or None

        if issue.get("cve"):
            finding.unsaved_vulnerability_ids = [issue["cve"]]
        cwe = self.cwe_number(issue.get("cwes"))
        if cwe:
            finding.cwe = cwe

    def is_vulnerability(self, issue):
        """
        Decide whether an issue is a security vulnerability.

        FOSSA sets type="vulnerability" for those, but the converter also treats an issue carrying
        vulnerability-only fields as one, so a missing or renamed type value cannot silently
        downgrade a CVE to a licensing finding.
        """
        if (issue.get("type") or "").strip().lower() == TYPE_VULNERABILITY:
            return True
        return bool(issue.get("cve") or issue.get("vulnId") or issue.get("cvssVector"))

    def severity(self, issue):
        if self.is_vulnerability(issue):
            graded = VULNERABILITY_SEVERITY.get((issue.get("severity") or "").strip().lower())
            # FOSSA reports "unknown" often enough that the CVSS bands matter.
            return graded or self.severity_from_cvss(issue.get("cvss") or 0)

        issue_type = (issue.get("type") or "").strip().lower()
        if issue_type in LICENSING_SEVERITY_BY_TYPE:
            return LICENSING_SEVERITY_BY_TYPE[issue_type]
        # An unrecognised risk_* signal is still quality noise; anything else is genuinely unknown.
        if issue_type.startswith("risk_"):
            return "Low"
        return "Info"

    def severity_from_cvss(self, score):
        """Grade a CVSS base score using the standard v3 bands."""
        with suppress(TypeError, ValueError):
            score = float(score)
            if score >= CVSS_CRITICAL_FLOOR:
                return "Critical"
            if score >= CVSS_HIGH_FLOOR:
                return "High"
            if score >= CVSS_MEDIUM_FLOOR:
                return "Medium"
            if score > 0:
                return "Low"
        return "Info"

    def vulnerability_title(self, issue, component, version):
        """Prefer "<CVE or vulnId> - <package> (<version>)", degrading as the converter does."""
        identifier = issue.get("cve") or issue.get("vulnId") or ""
        if not identifier:
            return issue.get("title") or f"FOSSA vulnerability {issue.get('id')}"
        if not component:
            return identifier
        title = f"{identifier} - {component}"
        if version:
            title += f" ({version})"
        return title

    def licensing_title(self, issue, component):
        """Render "<type> - <license> in <package>", omitting whichever parts FOSSA left empty."""
        title = (issue.get("type") or "").strip()
        if not title:
            title = f"FOSSA licensing issue {issue.get('id')}"
        if issue.get("license"):
            title += f" - {issue['license']}"
        if component:
            title += f" in {component}"
        return title

    def vulnerability_description(self, issue):
        lines = []
        if issue.get("details"):
            lines.append(issue["details"].strip() + "\n")

        self.write_package_lines(lines, issue)
        self.write_list_line(lines, "Affected versions", issue.get("affectedVersionRanges"))
        self.write_list_line(lines, "Patched versions", issue.get("patchedVersionRanges"))
        self.write_list_line(lines, "CWEs", issue.get("cwes"))
        self.write_list_line(lines, "CPEs", issue.get("cpes"))

        if issue.get("published"):
            lines.append(f"**Published:** {issue['published']}")
        if issue.get("cveStatus"):
            lines.append(f"**CVE status:** {issue['cveStatus']}")
        return "\n".join(lines).rstrip("\n")

    def licensing_description(self, issue):
        lines = []
        if issue.get("type"):
            lines.append(f"**Issue type:** {issue['type']}")
        if issue.get("license"):
            lines.append(f"**License:** {issue['license']}")
        self.write_package_lines(lines, issue)
        return "\n".join(lines).rstrip("\n")

    def write_package_lines(self, lines, issue):
        """
        Write the dependency coordinates and depths shared by every issue category.

        FOSSA is SCA, so these coordinates are the only location a finding has.
        """
        source = issue.get("source")
        if isinstance(source, dict):
            if source.get("id"):
                lines.append(f"**Package:** {source['id']}")
            if name := source.get("name"):
                version = source.get("version") or ""
                lines.append(f"**Dependency:** {name}@{version}" if version else f"**Dependency:** {name}")
            if source.get("packageManager"):
                lines.append(f"**Package manager:** {source['packageManager']}")
            if source.get("url"):
                lines.append(f"**Package URL:** {source['url']}")

        depths = issue.get("depths")
        if isinstance(depths, dict):
            direct, deep = depths.get("direct") or 0, depths.get("deep") or 0
            if direct > 0 or deep > 0:
                lines.append(f"**Dependency depths:** direct {direct}, transitive {deep}")

        lines.append(f"**FOSSA issue ID:** {issue.get('id')}")

    def write_list_line(self, lines, label, values):
        """Write one "**Label:** a, b, c" line, or nothing when the list is empty."""
        if not isinstance(values, list):
            return
        joined = ", ".join(str(v) for v in values if str(v).strip())
        if joined:
            lines.append(f"**{label}:** {joined}")

    def mitigation(self, issue):
        """
        Render FOSSA's upgrade advice.

        The complete fix, which resolves the issue, comes first, then any partial fix, each with the
        semver distance FOSSA reports for it.
        """
        remediation = issue.get("remediation")
        if not isinstance(remediation, dict):
            return ""

        lines = []
        for label, fix_key, distance_key in (
            ("Complete fix", "completeFix", "completeFixDistance"),
            ("Partial fix", "partialFix", "partialFixDistance"),
        ):
            if fix := remediation.get(fix_key):
                suffix = ""
                if distance := remediation.get(distance_key):
                    suffix = f" ({distance} version bump)"
                lines.append(f"**{label}:** upgrade to {fix}{suffix}")
        return "\n".join(lines)

    def references(self, issue):
        """
        Join the issue's reference links, one per line.

        FOSSA sends a reference as either a bare string or a {url, title} object, and the connector's
        Reference.Link() prefers the URL then the title.
        """
        refs = issue.get("references")
        if not isinstance(refs, list):
            return ""

        links = []
        for reference in refs:
            if isinstance(reference, str):
                link = reference
            elif isinstance(reference, dict):
                link = reference.get("url") or reference.get("title") or ""
            else:
                continue
            if link:
                links.append(link)
        return "\n".join(links)

    def tags(self, issue):
        category = TYPE_VULNERABILITY if self.is_vulnerability(issue) else "licensing"
        tags = []
        if issue.get("type"):
            tags.append(f"fossa:{issue['type']}")
        tags.append(f"category:{category}")

        source = issue.get("source")
        if isinstance(source, dict):
            if source.get("packageManager"):
                tags.append(f"package-manager:{source['packageManager']}")
            if source.get("id"):
                tags.append(source["id"])
        return tags

    def cwe_number(self, cwes):
        """Return the first parseable CWE in the list as an integer ("CWE-1321" -> 1321)."""
        if not isinstance(cwes, list):
            return 0
        for cwe in cwes:
            raw = str(cwe).strip().removeprefix("CWE-")
            with suppress(ValueError):
                number = int(raw)
                if number > 0:
                    return number
        return 0

    def date(self, timestamp):
        """
        Convert a FOSSA timestamp to a date.

        The converter falls back to the leading date portion for any timestamp shape the RFC3339
        parse rejects, so a truncated or oddly-formatted value still dates the finding.
        """
        trimmed = (timestamp or "").strip()
        if not trimmed:
            return None
        with suppress(ValueError):
            return datetime.fromisoformat(trimmed).date()
        with suppress(ValueError):
            return datetime.strptime(trimmed[:10], "%Y-%m-%d").date()
        return None
