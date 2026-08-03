import json
from contextlib import suppress
from datetime import UTC, datetime

from dojo.models import Finding

CATEGORY_SECURITY = "SECURITY"
CATEGORY_STYLE = "STYLE"
CATEGORY_DOCUMENTATION = "DOCUMENTATION"
CATEGORY_COVERAGE = "COVERAGE"

# Categories that describe a defect rather than a weakness. They are graded one step below the
# equivalent security issue, which is what the connector does.
RISK_CATEGORIES = frozenset({"BUG_RISK", "PERFORMANCE", "TYPECHECK", "ANTI_PATTERN"})

# DeepSource grades every issue CRITICAL / MAJOR / MINOR regardless of category, so the category
# decides which ladder applies. A security issue keeps its grade; a bug-risk issue drops a step.
SECURITY_SEVERITY = {"CRITICAL": "Critical", "MAJOR": "High", "MINOR": "Medium"}
RISK_SEVERITY = {"CRITICAL": "High", "MAJOR": "Medium", "MINOR": "Low"}

# A hit from the secrets analyzer is a committed credential whatever DeepSource graded it.
SECRETS_ANALYZER = "secrets"

# CVSS v3 band floors, used for dependency advisories that carry a score.
CVSS_CRITICAL_FLOOR = 9.0
CVSS_HIGH_FLOOR = 7.0
CVSS_MEDIUM_FLOOR = 4.0

# Advisory severity words, including GitHub's "MODERATE" spelling of medium.
NAMED_SEVERITY = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "MODERATE": "Medium",
    "LOW": "Low",
}

DEFAULT_SEVERITY = "Info"


class DeepSourceParser:

    """
    Parses a DeepSource export.

    Mirrors pkg/tools/deepsource/converter field for field so a file import and an API sync
    deduplicate against each other instead of producing two copies of everything.

    DeepSource reports two different things, and the connector converts them differently: static
    ANALYSIS ISSUES found in the code, and DEPENDENCY VULNERABILITIES from advisories. Both are
    accepted here; see get_fields() for the two mappings.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanType().
        return ["DeepSource - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "DeepSource - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a DeepSource export (JSON). Accepts both analysis issue occurrences and "
            "dependency vulnerabilities. Matches the scan type used by the DeepSource connector so "
            "file and API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the DeepSource Parser.

        For an ANALYSIS ISSUE occurrence:
        - title: the occurrence title, then the issue title, then its shortcode.
        - severity: see severity_for_issue - the category decides which ladder applies.
        - description: the issue's short description, then issue shortcode, analyzer, category,
          DeepSource's own severity word, and the file location.
        - file_path / line: where the occurrence is.
        - vuln_id_from_tool: the DeepSource issue shortcode, e.g. PY-A6006.

        For a DEPENDENCY VULNERABILITY:
        - title: "<advisory id> - <package> (<version>)", degrading as the converter's does.
        - severity: the CVSS v3 band when scored, otherwise the advisory's severity word.
        - description: the advisory summary, package, ecosystem, reachability, fixability, aliases.
        - mitigation: the fixed versions, or a note that none has been published.
        - component_name / component_version, cvssv3_score, epss_score, references.

        Both carry unique_id_from_tool - the occurrence or vulnerability id - and are static.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "mitigation",
            "references",
            "cvssv3_score",
            "epss_score",
            "file_path",
            "line",
            "component_name",
            "component_version",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "tags",
            "active",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the DeepSource Parser.

        Copied from the DeepSource block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. Diverging would stop file findings
        merging with API-synced ones.
        """
        return ["title", "severity", "file_path"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        occurrences, vulnerabilities, run = self.extract(data)

        findings = {}
        for occurrence in occurrences:
            if isinstance(occurrence, dict):
                finding = self.build_occurrence(occurrence, run, test)
                findings.setdefault(finding.unique_id_from_tool, finding)
        for vulnerability in vulnerabilities:
            if isinstance(vulnerability, dict):
                finding = self.build_vulnerability(vulnerability, test)
                findings.setdefault(finding.unique_id_from_tool, finding)
        return list(findings.values())

    def extract(self, data):
        """
        Split a DeepSource GraphQL response into occurrences, vulnerabilities and the analysis run.

        DeepSource has no REST API - everything goes through POST /graphql/ - so the file a user can
        actually produce is a saved GraphQL response:

            {"data": {"repository": {
                "analysisRuns": {"edges": [{"node": {...}}]},
                "issueOccurrences": {"edges": [{"node": {...}}]},
                "dependencyVulnerabilityOccurrences": {"edges": [{"node": {...}}]}}}}

        Both queries return the same repository envelope, so one file may carry either connection or
        both. The edges/node wrapping is unwrapped here.
        """
        repository = self.repository(data)
        if repository is not None:
            occurrences = self.nodes(repository.get("issueOccurrences"))
            vulnerabilities = self.nodes(repository.get("dependencyVulnerabilityOccurrences"))
            runs = self.nodes(repository.get("analysisRuns"))
            run = runs[0] if runs else None
            return occurrences, vulnerabilities, run

        # Convenience shapes, for anyone who has already unwrapped the response themselves.
        if isinstance(data, list):
            occurrences = [row for row in data if not self.looks_like_vulnerability(row)]
            vulnerabilities = [row for row in data if self.looks_like_vulnerability(row)]
            return occurrences, vulnerabilities, None

        if isinstance(data, dict):
            occurrences, found_occurrences = self.first_list(data, ("occurrences", "issues"))
            vulnerabilities, found_vulnerabilities = self.first_list(
                data, ("vulnerabilities", "dependencyVulnerabilities"),
            )
            run = data.get("run") if isinstance(data.get("run"), dict) else None
            # Presence of the key is what identifies the shape, not whether it has entries: a clean
            # run legitimately reports both lists empty.
            if found_occurrences or found_vulnerabilities:
                return occurrences, vulnerabilities, run

        msg = (
            "A DeepSource export is a saved GraphQL response with data.repository containing "
            "issueOccurrences or dependencyVulnerabilityOccurrences; got "
            f"{type(data).__name__}."
        )
        raise TypeError(msg)

    def repository(self, data):
        """
        Find the repository object in a GraphQL response, whether or not the "data" wrapper is kept.

        Returns None when this is not a GraphQL response at all, so the caller can try the
        convenience shapes.
        """
        if not isinstance(data, dict):
            return None
        for candidate in (data.get("data"), data):
            if isinstance(candidate, dict):
                repository = candidate.get("repository")
                if isinstance(repository, dict):
                    return repository
        return None

    def nodes(self, connection):
        """Unwrap a GraphQL connection's edges into a plain list of nodes."""
        if not isinstance(connection, dict):
            return []
        edges = connection.get("edges")
        if not isinstance(edges, list):
            return []
        return [
            edge["node"] for edge in edges
            if isinstance(edge, dict) and isinstance(edge.get("node"), dict)
        ]

    def first_list(self, data, keys):
        """Return the first list found under these keys, and whether any of them was present."""
        for key in keys:
            if isinstance(data.get(key), list):
                return data[key], True
        return [], False

    def looks_like_vulnerability(self, row):
        return isinstance(row, dict) and isinstance(row.get("vulnerability"), dict)

    def build_occurrence(self, occurrence, run, test):
        issue = occurrence.get("issue") or {}
        begin = occurrence.get("beginLine") or 0

        finding = Finding(
            test=test,
            title=self.occurrence_title(occurrence, issue),
            severity=self.severity_for_issue(issue),
            date=self.run_date(run),
            description=self.occurrence_description(occurrence, issue, begin),
            file_path=occurrence.get("path") or None,
            line=begin or None,
            unique_id_from_tool=occurrence.get("id"),
            vuln_id_from_tool=issue.get("shortcode") or None,
            active=True,
            # DeepSource analyses source, never a running service.
            static_finding=True,
            dynamic_finding=False,
        )
        analyzer = issue.get("analyzer") or {}
        finding.unsaved_tags = [
            value.strip() for value in
            (analyzer.get("shortcode"), issue.get("category"), issue.get("severity"))
            if (value or "").strip()
        ]
        return finding

    def occurrence_title(self, occurrence, issue):
        for candidate in (occurrence.get("title"), issue.get("title"), issue.get("shortcode")):
            if (candidate or "").strip():
                return candidate.strip()
        return f"DeepSource issue {occurrence.get('id')}"

    def occurrence_description(self, occurrence, issue, begin):
        sections = []
        if (issue.get("shortDescription") or "").strip():
            sections.append(issue["shortDescription"].strip())

        analyzer = issue.get("analyzer") or {}
        details = []
        if issue.get("shortcode"):
            details.append(f"**Issue:** {issue['shortcode']}")
        if analyzer.get("name") or analyzer.get("shortcode"):
            details.append(f"**Analyzer:** {self.analyzer_label(analyzer)}")
        if issue.get("category"):
            details.append(f"**Category:** {issue['category']}")
        if issue.get("severity"):
            details.append(f"**DeepSource severity:** {issue['severity']}")
        if occurrence.get("path"):
            details.append(f"**Location:** {occurrence['path']}{self.line_range(occurrence, begin)}")

        if details:
            sections.append("\n".join(details))
        return "\n\n".join(sections)

    def analyzer_label(self, analyzer):
        name, shortcode = analyzer.get("name") or "", analyzer.get("shortcode") or ""
        if name and shortcode:
            return f"{name} ({shortcode})"
        return name or shortcode

    def line_range(self, occurrence, begin):
        """A range only when the occurrence genuinely spans more than one line."""
        if not begin:
            return ""
        end = occurrence.get("endLine") or 0
        return f":{begin}-{end}" if end > begin else f":{begin}"

    def severity_for_issue(self, issue):
        """
        Grade an analysis issue.

        DeepSource grades everything CRITICAL / MAJOR / MINOR regardless of what the issue actually
        is, so the category decides which ladder applies: a security issue keeps its grade, while a
        bug-risk, performance, typecheck or anti-pattern issue drops a step, because those describe a
        defect rather than a weakness. Style, documentation and coverage are Info.

        A hit from the secrets analyzer is a committed credential whatever the grade said, so it
        outranks both ladders.
        """
        analyzer = issue.get("analyzer") or {}
        if (analyzer.get("shortcode") or "").strip().lower() == SECRETS_ANALYZER:
            return "Critical"

        severity = (issue.get("severity") or "").strip().upper()
        category = (issue.get("category") or "").strip().upper()

        if category == CATEGORY_SECURITY:
            if severity in SECURITY_SEVERITY:
                return SECURITY_SEVERITY[severity]
        elif category in RISK_CATEGORIES:
            if severity in RISK_SEVERITY:
                return RISK_SEVERITY[severity]
        elif category in {CATEGORY_STYLE, CATEGORY_DOCUMENTATION, CATEGORY_COVERAGE}:
            return "Info"
        return DEFAULT_SEVERITY

    def build_vulnerability(self, occurrence, test):
        vulnerability = occurrence.get("vulnerability") or {}
        package = occurrence.get("package") or {}
        version = (occurrence.get("packageVersion") or {}).get("version") or ""

        references = vulnerability.get("referenceUrls")
        finding = Finding(
            test=test,
            title=self.vulnerability_title(occurrence, vulnerability, package, version),
            severity=self.severity_for_vulnerability(vulnerability),
            date=self.published_date(vulnerability.get("publishedAt")),
            description=self.vulnerability_description(occurrence, vulnerability, package, version),
            mitigation=self.vulnerability_mitigation(vulnerability, package),
            references="\n".join(references) if isinstance(references, list) else None,
            cvssv3_score=vulnerability.get("cvssV3BaseScore") or None,
            epss_score=vulnerability.get("epssScore") or None,
            component_name=package.get("name") or None,
            component_version=version or None,
            unique_id_from_tool=occurrence.get("id"),
            vuln_id_from_tool=vulnerability.get("identifier") or None,
            active=True,
            static_finding=True,
            dynamic_finding=False,
        )
        finding.unsaved_tags = ["sca"] + [
            value.strip() for value in (package.get("ecosystem"), occurrence.get("reachability"))
            if (value or "").strip()
        ]
        identifiers = self.vulnerability_ids(vulnerability)
        if identifiers:
            finding.unsaved_vulnerability_ids = identifiers
        return finding

    def vulnerability_title(self, occurrence, vulnerability, package, version):
        identifier = (vulnerability.get("identifier") or "").strip()
        component = (package.get("name") or "").strip()
        if identifier and component and version:
            return f"{identifier} - {component} ({version})"
        if identifier and component:
            return f"{identifier} - {component}"
        if identifier:
            return identifier
        if (vulnerability.get("summary") or "").strip():
            return vulnerability["summary"].strip()
        return f"DeepSource dependency vulnerability {occurrence.get('id')}"

    def vulnerability_description(self, occurrence, vulnerability, package, version):
        sections = []
        if (vulnerability.get("summary") or "").strip():
            sections.append(vulnerability["summary"].strip())

        details = []
        if package.get("name"):
            component = f"{package['name']} {version}".strip() if version else package["name"]
            details.append(f"**Package:** {component}")
        if package.get("ecosystem"):
            details.append(f"**Ecosystem:** {package['ecosystem']}")
        if occurrence.get("reachability"):
            details.append(f"**Reachability:** {occurrence['reachability']}")
        if occurrence.get("fixability"):
            details.append(f"**Fixability:** {occurrence['fixability']}")
        if vulnerability.get("cvssV3Severity"):
            details.append(f"**CVSS v3 severity:** {vulnerability['cvssV3Severity']}")
        aliases = vulnerability.get("aliases")
        if isinstance(aliases, list) and aliases:
            details.append("**Aliases:** " + ", ".join(str(a) for a in aliases))

        if details:
            sections.append("\n".join(details))
        return "\n\n".join(sections)

    def vulnerability_mitigation(self, vulnerability, package):
        """
        Name the versions that fix the advisory.

        The connector says so explicitly when there are none, rather than leaving the field empty -
        "no fix published" is itself useful triage information.
        """
        fixed = vulnerability.get("fixedVersions")
        versions = [str(v).strip() for v in fixed if str(v).strip()] if isinstance(fixed, list) else []
        if not versions:
            return "No fixed version has been published for this advisory."
        component = package.get("name") or "the affected package"
        return f"Upgrade {component} to {' or '.join(versions)}."

    def severity_for_vulnerability(self, vulnerability):
        """A scored advisory is graded by CVSS band; otherwise its severity word decides."""
        score = vulnerability.get("cvssV3BaseScore") or 0
        if score > 0:
            return self.cvss_band(score)
        for candidate in (vulnerability.get("cvssV3Severity"), vulnerability.get("severity")):
            named = NAMED_SEVERITY.get((candidate or "").strip().upper())
            if named:
                return named
        return DEFAULT_SEVERITY

    def cvss_band(self, score):
        """Note the converter's lowest band is Low, not Info - a scored advisory is never Info."""
        if score >= CVSS_CRITICAL_FLOOR:
            return "Critical"
        if score >= CVSS_HIGH_FLOOR:
            return "High"
        if score >= CVSS_MEDIUM_FLOOR:
            return "Medium"
        return "Low"

    def vulnerability_ids(self, vulnerability):
        """The advisory identifier then its aliases, upper-cased and deduplicated in order."""
        aliases = vulnerability.get("aliases")
        candidates = [vulnerability.get("identifier") or ""]
        if isinstance(aliases, list):
            candidates.extend(str(alias) for alias in aliases)

        identifiers, seen = [], set()
        for candidate in candidates:
            upper = candidate.strip().upper()
            if upper and upper not in seen:
                seen.add(upper)
                identifiers.append(upper)
        return identifiers

    def run_date(self, run):
        """
        The analysis run's finish time, falling back to when it was created, then to today.

        The connector always dates a finding rather than leaving it unset; mirrored here.
        """
        if isinstance(run, dict):
            for candidate in (run.get("finishedAt"), run.get("createdAt")):
                parsed = self.parse_date(candidate)
                if parsed:
                    return parsed
        return datetime.now(tz=UTC).date()

    def published_date(self, published_at):
        return self.parse_date(published_at) or datetime.now(tz=UTC).date()

    def parse_date(self, value):
        with suppress(ValueError, AttributeError):
            return datetime.fromisoformat((value or "").strip()).astimezone(UTC).date()
        return None
