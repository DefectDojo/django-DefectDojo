import json
import re
from contextlib import suppress

from dojo.models import Finding

# Mirrors the connector's own regular expressions, which in turn mirror DefectDojo's SARIF parser.
CWE_PATTERN = re.compile(r"cwe-(\d+)", re.IGNORECASE)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

SEVERITY_BY_LEVEL = {"note": "Info", "warning": "Medium", "error": "High"}
SEVERITY_BY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
}
# A SARIF result with no level is Medium, NOT Info - see severity().
DEFAULT_SEVERITY = "Medium"

TITLE_MAX_LENGTH = 150
CWE_TAG_PREFIX = "external/cwe/"


class SarifConnectorFindings:

    """
    The SARIF mapping shared by every connector that reports SARIF.

    On the Go side these connectors share one utility (pkg/utils/sarif), parameterised by a PREFIX for
    the identity and a static/dynamic flag. Mirroring that here as a mixin is what keeps the parsers
    from drifting apart: a change to the shared mapping has to land in one place, exactly as it does
    upstream. The shipped invicti parser extends netsparker the same way.

    NOT registered as a parser itself - dojo/tools/factory.py only registers the class whose lowercased
    name matches its module, so this one is invisible to it.
    """

    # Overridden per vendor: the identity prefix, and whether the tool reads an artifact or runs it.
    tool_prefix = ""
    is_static = True

    def scope_id(self, data):
        """The id that namespaces every identity - a scan, an assessment. Overridden per vendor."""
        return ""

    def prepare(self, data):
        """
        Hook run once, before any finding is built.

        A vendor that decorates its findings with context the SARIF document does not carry reads that
        context here, rather than as a side effect of something else. Does nothing by default.
        """

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, dict):
            msg = (
                f"A {self.vendor} export is a SARIF log, a JSON object with a 'runs' list; got "
                f"{type(data).__name__}."
            )
            raise TypeError(msg)

        self.prepare(data)
        scope = self.scope_id(data)
        log = self.log(data)
        runs = log.get("runs")
        if not isinstance(runs, list):
            msg = f"A {self.vendor} export is a SARIF log; this object has no 'runs' list."
            raise TypeError(msg)

        findings = []
        for run in runs:
            if not isinstance(run, dict):
                continue
            rules = self.rules_by_id(run)
            for result in run.get("results") or []:
                if not isinstance(result, dict):
                    continue
                if finding := self.build_finding(result, rules, scope, test):
                    findings.append(finding)
        return findings

    def log(self, data):
        """
        The SARIF log itself, unwrapped from whatever envelope supplied the scope id.

        A downloaded log has no envelope at all, and then it is the log.
        """
        for key in ("sarif", "log", "report"):
            if isinstance(data.get(key), dict):
                return data[key]
        return data

    def scope_from(self, data, keys):
        """
        The scope id, read from whichever spelling the file uses.

        It is part of every identity the connector builds and a downloaded SARIF log does not carry it,
        so WITHOUT it the identities differ from the connector's and file findings will not deduplicate
        against synced ones.
        """
        for key in keys:
            if value := str(data.get(key) or "").strip():
                return value
        return ""

    def rules_by_id(self, run):
        """The run's rule definitions, keyed by id, so a result can be read with its rule."""
        driver = self.block(self.block(run, "tool"), "driver")
        rules = {}
        for rule in driver.get("rules") or []:
            if isinstance(rule, dict):
                rules[str(rule.get("id") or "")] = rule
        return rules

    def block(self, row, key):
        if not isinstance(row, dict):
            return {}
        value = row.get(key)
        return value if isinstance(value, dict) else {}

    def text(self, holder, key):
        """A SARIF multiformatMessageString: {"text": "..."}."""
        return str(self.block(holder, key).get("text") or "")

    def build_finding(self, result, rules, scope, test):
        kind = str(result.get("kind") or "")
        if kind and kind != "fail":
            # SARIF uses kind for results that are not failures at all - "pass", "open",
            # "informational". Importing those would fill the product with non-findings.
            return None

        rule_id = str(result.get("ruleId") or "")
        rule = rules.get(rule_id)
        suppressed = bool(result.get("suppressions"))
        file_path, line = self.location(result)

        finding = Finding(
            test=test,
            title=self.title(result, rule),
            severity=self.severity(result, rule),
            description=self.describe(result, rule),
            file_path=file_path or None,
            line=line or None,
            references=self.references(rule) or None,
            unique_id_from_tool=f"{self.tool_prefix}-{scope}-{rule_id}-{file_path}:{line}",
            vuln_id_from_tool=rule_id or None,
            # Whether the tool reads an artifact or exercises it is the one thing the shared
            # mapping cannot decide for itself.
            static_finding=self.is_static,
            dynamic_finding=not self.is_static,
            # A suppressed result is BOTH inactive and a false positive: SARIF suppression is a
            # reviewer saying this one does not count, which is what false_p records.
            active=not suppressed,
            false_p=suppressed,
        )
        finding.cvssv3_score = self.security_severity_score(rule)
        finding.unsaved_tags = self.tags(result, rule)

        if match := CVE_PATTERN.search(rule_id):
            finding.unsaved_vulnerability_ids = [match.group(0).upper()]
        if cwe := self.cwe(result, rule):
            finding.cwe = cwe
        if fix := self.fixes(result):
            finding.mitigation = fix
        self.decorate(finding, result)
        return finding

    def decorate(self, finding, result):
        """Hook for the context a SARIF document does not carry. Does nothing by default."""

    def title(self, result, rule):
        if message := self.text(result, "message"):
            return self.shorten(message)
        if rule is not None:
            for key in ("shortDescription", "fullDescription"):
                if value := self.text(rule, key):
                    return self.shorten(value)
            return str(rule.get("name") or "") or str(rule.get("id") or "")
        return str(result.get("ruleId") or "")

    def describe(self, result, rule):
        """
        The result message, then the rule's name and descriptions - each only when it adds something.

        A rule whose short description merely repeats the message, or whose full description repeats
        the short one, is not printed twice.
        """
        message = self.text(result, "message")
        lines = []
        if message:
            lines.append(f"**Result message:** {message}")

        if rule is not None:
            if name := str(rule.get("name") or ""):
                lines.append(f"**Rule name:** {name}")
            short = self.text(rule, "shortDescription")
            if short and short != message:
                lines.append(f"**Rule short description:** {short}")
            full = self.text(rule, "fullDescription")
            if full and full != short:
                lines.append(f"**Rule full description:** {full}")
        return "\n".join(lines).strip()

    def severity(self, result, rule):
        """
        The rule's security-severity property, read as a CVSS score and then as a word.

        A result with NO level is Medium rather than Info: SARIF makes level optional and a tool that
        omits it is not saying the result is harmless. Defaulting to Info would silently bury it.
        """
        if rule is not None:
            raw = str(self.block(rule, "properties").get("security-severity") or "")
            if raw:
                with suppress(ValueError):
                    return self.cvss_severity(float(raw))
                if mapped := SEVERITY_BY_LABEL.get(raw.strip().lower()):
                    return mapped
        return SEVERITY_BY_LEVEL.get(str(result.get("level") or ""), DEFAULT_SEVERITY)

    def cvss_severity(self, score):
        if score >= 9:
            return "Critical"
        if score >= 7:
            return "High"
        if score >= 4:
            return "Medium"
        if score > 0:
            return "Low"
        return "Info"

    def security_severity_score(self, rule):
        """The security-severity property when it is a number; a word scores nothing."""
        if rule is None:
            return 0.0
        with suppress(ValueError):
            return float(str(self.block(rule, "properties").get("security-severity") or ""))
        return 0.0

    def location(self, result):
        """The first physical location - the file inside the model archive, and its line."""
        for location in result.get("locations") or []:
            if not isinstance(location, dict):
                continue
            physical = self.block(location, "physicalLocation")
            if not physical:
                continue
            file_path = str(self.block(physical, "artifactLocation").get("uri") or "")
            line = self.integer(self.block(physical, "region").get("startLine"))
            return file_path, line
        return "", 0

    def references(self, rule):
        """The rule's help URI, or its help text when that is itself a link."""
        if rule is None:
            return ""
        if uri := str(rule.get("helpUri") or ""):
            return uri
        help_text = self.text(rule, "help")
        if help_text.startswith("http"):
            return help_text
        return ""

    def cwe(self, result, rule):
        """
        A CWE id from the rule's relationships, then its tags, then the result's tags.

        SARIF has no CWE field: a tool states the taxonomy either as a relationship target or as a
        tag like "external/cwe/cwe-502", so both are searched.
        """
        if rule is not None:
            for relationship in rule.get("relationships") or []:
                if isinstance(relationship, dict):
                    if cwe := self.parse_cwe(str(self.block(relationship, "target").get("id") or "")):
                        return cwe
            if cwe := self.first_cwe(self.block(rule, "properties").get("tags")):
                return cwe
        return self.first_cwe(self.block(result, "properties").get("tags"))

    def first_cwe(self, tags):
        for tag in tags or []:
            if cwe := self.parse_cwe(str(tag)):
                return cwe
        return 0

    def parse_cwe(self, value):
        if match := CWE_PATTERN.search(value):
            with suppress(ValueError):
                return int(match.group(1))
        return 0

    def fixes(self, result):
        """Every fix description the result carries, one per line."""
        texts = [
            self.text(fix, "description")
            for fix in result.get("fixes") or []
            if isinstance(fix, dict) and self.text(fix, "description")
        ]
        return "\n".join(texts)

    def tags(self, result, rule):
        """
        The rule's tags then the result's, deduplicated, with the CWE taxonomy prefix stripped.

        "external/cwe/cwe-502" reads as "cwe-502", matching DefectDojo's own SARIF parser.
        """
        tags = []
        for holder in ((rule if rule is not None else {}), result):
            for tag in self.block(holder, "properties").get("tags") or []:
                clean = str(tag).removeprefix(CWE_TAG_PREFIX)
                if clean and clean not in tags:
                    tags.append(clean)
        return tags

    def shorten(self, text):
        """At most 150 characters, ending in an ellipsis when cut, as the connector does."""
        if len(text) <= TITLE_MAX_LENGTH:
            return text
        return text[: TITLE_MAX_LENGTH - 3] + "..."

    def integer(self, value):
        """SARIF numbers may arrive quoted, which the connector's own decoder tolerates."""
        if isinstance(value, bool) or value is None:
            return 0
        if isinstance(value, int | float):
            return int(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return int(float(value.strip() or 0))
        return 0


class HiddenlayerParser(SarifConnectorFindings):

    """
    Parses a HiddenLayer model-scan SARIF log.

    Mirrors pkg/tools/hiddenlayer/connector/finding_converter field for field so a file import and an
    API sync deduplicate against each other instead of producing two copies of everything.

    HiddenLayer scans machine-learning models and reports SARIF. DefectDojo ships a generic SARIF
    parser, but importing through it would record the findings under the "SARIF" scan type, where they
    would NOT deduplicate against the HiddenLayer connector's - which is the whole reason this exists.
    The mapping is the connector's, which itself mirrors dojo/tools/sarif/parser.py.
    """

    vendor = "HiddenLayer"
    tool_prefix = "hiddenlayer"
    # A model scan reads an artifact; nothing is exercised.
    is_static = True

    def scope_id(self, data):
        """HiddenLayer namespaces its identities by scan id."""
        return self.scope_from(data, ("scan_id", "scanId", "scanID"))

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["HiddenLayer Model Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "HiddenLayer Model Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a HiddenLayer model-scan SARIF log. Matches the scan type used by the HiddenLayer "
            "connector so file and API findings deduplicate - give the scan's scan_id to deduplicate "
            "against connector findings."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the HiddenLayer Parser.

        Mirrors the connector's convertResult:
        - title: the result message, then the rule's short then full description, then its name or id.
          Shortened to 150 characters.
        - severity: the rule's security-severity property as a CVSS score, then as a word, then the
          result level - defaulting to Medium; see severity().
        - description: the result message and the rule's name and descriptions.
        - cvssv3_score: the security-severity property, when it is a number.
        - cwe: from the rule's relationships, then the rule's tags, then the result's tags.
        - file_path / line: the first physical location.
        - active / false_p: a suppressed result is inactive AND a false positive.
        - unique_id_from_tool: "hiddenlayer-<scan id>-<rule id>-<file>:<line>".
        """
        return [
            "title",
            "severity",
            "description",
            "cvssv3_score",
            "cwe",
            "file_path",
            "line",
            "mitigation",
            "references",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "unsaved_vulnerability_ids",
            "tags",
            "active",
            "false_p",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the HiddenLayer Parser.

        Copied from the HiddenLayer block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. The file path is in the hash because
        one rule firing on two files in a model archive is two findings.
        """
        return ["title", "severity", "file_path"]
