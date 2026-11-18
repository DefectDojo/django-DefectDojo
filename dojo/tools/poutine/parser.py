import json
import logging

from packageurl import PackageURL

from dojo.models import Finding

logger = logging.getLogger(__name__)

# poutine rules carry a SARIF-style level
SEVERITY_MAPPING = {
    "error": "High",
    "warning": "Medium",
    "note": "Low",
    "none": "Info",
}

# Base URL of the per-rule documentation, as used by poutine's own SARIF output (helpUri)
RULE_DOCUMENTATION_URL = "https://boostsecurityio.github.io/poutine/rules/"


class PoutineParser:

    """
    Parser for the JSON output of poutine (https://github.com/boostsecurityio/poutine), a supply chain
    scanner for build pipelines.

    The report (`poutine analyze_local . --format json`) has three keys: `findings`, `rules` (the
    definition of every rule, keyed by rule id) and `packages` (one entry per analyzed repository).
    """

    def get_scan_types(self):
        return ["poutine Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import the JSON output of poutine (poutine analyze_local . --format json), a supply chain scanner for GitHub Actions and GitLab CI pipelines."

    def get_findings(self, file, test):
        data = self._load_json(file)
        rules = data.get("rules") or {}
        items = data.get("findings") or []
        if not items:
            logger.info("poutine report contains no findings")
        return [self._build_finding(item, rules.get(item.get("rule_id")) or {}) for item in items]

    def _load_json(self, file):
        content = file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            msg = "Invalid poutine report: the file is not valid JSON. Generate it with 'poutine --format json'."
            raise ValueError(msg) from e
        if not isinstance(data, dict) or "findings" not in data or not isinstance(data["findings"], list | None):
            msg = "Invalid poutine report: expected a JSON object with a 'findings' list as produced by 'poutine --format json'."
            raise ValueError(msg)
        return data

    def _build_finding(self, item, rule):
        rule_id = item.get("rule_id")
        meta = item.get("meta") or {}
        line = meta.get("line")
        documentation_url = f"{RULE_DOCUMENTATION_URL}{rule_id}" if rule_id else None
        references = [documentation_url] if documentation_url else []
        references.extend(ref.get("ref") for ref in rule.get("refs") or [] if ref.get("ref"))

        finding = Finding(
            title=rule.get("title") or rule_id,
            severity=SEVERITY_MAPPING.get(rule.get("level"), "Info"),
            description=self._description(item, rule, meta, documentation_url),
            references="\n".join(references) or None,
            vuln_id_from_tool=rule_id,
            file_path=meta.get("path"),
            line=line if isinstance(line, int) and line > 0 else None,
            static_finding=True,
            dynamic_finding=False,
        )
        if meta.get("osv_id"):
            finding.unsaved_vulnerability_ids = [meta["osv_id"]]
        repository = self._repository(item.get("purl"))
        if repository:
            # analyze_org / analyze_repo reports can cover several repositories in one report.
            # The service field is part of every hash code, so findings in different repositories
            # that share a workflow path and line are not deduplicated against each other.
            finding.service = repository
        return finding

    def _repository(self, purl):
        """Return owner/repo for a remote repository purl (pkg:github/owner/repo). Local scans return None."""
        if not purl:
            return None
        try:
            package_url = PackageURL.from_string(purl)
        except ValueError:
            return None
        if package_url.type == "localrepo":
            return None
        return "/".join(part for part in (package_url.namespace, package_url.name) if part) or None

    def _description(self, item, rule, meta, documentation_url):
        lines = []
        if rule.get("description"):
            lines.extend([rule["description"], ""])
        lines.append(f"**Rule:** {item.get('rule_id')}")
        if meta.get("details"):
            lines.append(f"**Details:** {meta['details']}")
        location = meta.get("path") or "unknown file"
        if meta.get("line"):
            location += f":{meta['line']}"
        lines.append(f"**Location:** {location}")
        if item.get("purl"):
            lines.append(f"**Repository:** {item['purl']}")
        for key, label in (("job", "Job"), ("step", "Step"), ("osv_id", "Advisory"), ("lotp_tool", "Living-off-the-pipeline tool")):
            if meta.get(key) not in {None, ""}:
                lines.append(f"**{label}:** {meta[key]}")
        for key, label in (
            ("event_triggers", "Event triggers"),
            ("injection_sources", "Injection sources"),
            ("referenced_secrets", "Referenced secrets"),
            ("lotp_targets", "Living-off-the-pipeline targets"),
        ):
            values = meta.get(key) or []
            if values:
                lines.append(f"**{label}:** {', '.join(str(value) for value in values)}")
        if documentation_url:
            lines.append(f"**Documentation and remediation:** {documentation_url}")
        return "\n".join(lines)
