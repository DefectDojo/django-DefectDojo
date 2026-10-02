import json

import dateutil.parser

from dojo.models import Finding
from dojo.tools.csaf.product_tree import ProductTree

# CSAF product_status buckets (CSAF 2.0 section 3.2.3.9), and how each affects the finding's state.
STATUS_KNOWN_AFFECTED = "known_affected"
STATUS_KNOWN_NOT_AFFECTED = "known_not_affected"
STATUS_FIXED = "fixed"
STATUS_UNDER_INVESTIGATION = "under_investigation"
STATUS_FIRST_AFFECTED = "first_affected"
STATUS_LAST_AFFECTED = "last_affected"
STATUS_FIRST_FIXED = "first_fixed"
STATUS_RECOMMENDED = "recommended"

# Buckets that assert exposure, and buckets that assert the opposite. Order matters when a product
# somehow appears in more than one: affected wins, because under-reporting exposure is the worse error.
AFFECTED_BUCKETS = (STATUS_KNOWN_AFFECTED, STATUS_FIRST_AFFECTED, STATUS_LAST_AFFECTED)
FIXED_BUCKETS = (STATUS_FIXED, STATUS_FIRST_FIXED, STATUS_RECOMMENDED)

# CVSS v3 qualitative ratings, mapped to DefectDojo severities.
CVSS3_SEVERITY = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "NONE": "Info",
}


class CsafParser:

    """
    CSAF 2.0 (Common Security Advisory Framework) is the OASIS standard for machine-readable vendor
    security advisories, and the format CISA has driven adoption of. Vendors including Red Hat, SUSE,
    Cisco and Siemens publish their advisories as CSAF.

    One finding is created per (vulnerability, product) pair, because a single advisory routinely
    covers many products with different states - one product patched, another still exposed.

    ★ `known_not_affected` products do NOT import as active findings. The advisory explicitly states
    those products are not exposed; importing them as active would turn a vendor's "you are fine" into
    work, in the same way a mishandled VEX statement would.

    https://oasis-open.github.io/csaf-documentation/
    """

    def get_scan_types(self):
        return ["CSAF Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "CSAF Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import CSAF 2.0 vendor security advisories (JSON). One finding per vulnerability and "
            "product; known_not_affected products are imported inactive."
        )

    def get_findings(self, file, test):
        data = json.load(file)
        if not isinstance(data, dict):
            msg = "This CSAF file is not an object; expected a CSAF advisory document."
            raise TypeError(msg)

        document = data.get("document") or {}
        self._check_version(document)

        tree = ProductTree(data.get("product_tree"))
        report_date = self._report_date(document)
        advisory_title = (document.get("title") or "").strip()
        publisher = self._publisher(document)

        findings = {}
        for vulnerability in data.get("vulnerabilities", []) or []:
            if not isinstance(vulnerability, dict):
                continue
            for finding in self._vulnerability_findings(
                vulnerability, tree, test, report_date, advisory_title, publisher,
            ):
                findings.setdefault(finding.unique_id_from_tool, finding)

        return list(findings.values())

    def _check_version(self, document):
        """Reject anything that is not CSAF 2.x, rather than mis-reading a different schema."""
        version = (document.get("csaf_version") or "").strip()
        if version and not version.startswith("2"):
            msg = (
                f"CSAF version {version} is not supported; this parser reads CSAF 2.0. "
                "CSAF 1.x used the older CVRF schema."
            )
            raise ValueError(msg)

    def _report_date(self, document):
        tracking = document.get("tracking") or {}
        for key in ("current_release_date", "initial_release_date"):
            if raw := (tracking.get(key) or "").strip():
                try:
                    return dateutil.parser.parse(raw)
                except (ValueError, OverflowError, dateutil.parser.ParserError):
                    continue
        return None

    def _publisher(self, document):
        publisher = document.get("publisher") or {}
        name = (publisher.get("name") or "").strip()
        category = (publisher.get("category") or "").strip()
        if name and category:
            return f"{name} ({category})"
        return name or category

    # -- per-vulnerability ----------------------------------------------------------------------------

    def _vulnerability_findings(self, vulnerability, tree, test, report_date, advisory_title, publisher):
        identifier = self._identifier(vulnerability)
        if not identifier:
            return

        product_status = vulnerability.get("product_status") or {}
        scores_by_product = self._scores_by_product(vulnerability)
        remediations_by_product = self._remediations_by_product(vulnerability)

        # Walk every status bucket the advisory used, so a product listed only as fixed or only as
        # not-affected still produces its (inactive) finding rather than being dropped.
        for bucket, product_ids in product_status.items():
            if not isinstance(product_ids, list):
                continue
            for raw_product_id in product_ids:
                product_id = str(raw_product_id).strip()
                if not product_id:
                    continue
                yield self._build_finding(
                    vulnerability=vulnerability,
                    identifier=identifier,
                    bucket=bucket,
                    product_id=product_id,
                    tree=tree,
                    scores_by_product=scores_by_product,
                    remediations_by_product=remediations_by_product,
                    test=test,
                    report_date=report_date,
                    advisory_title=advisory_title,
                    publisher=publisher,
                )

    def _build_finding(self, **kwargs):
        vulnerability = kwargs["vulnerability"]
        identifier = kwargs["identifier"]
        bucket = kwargs["bucket"]
        product_id = kwargs["product_id"]
        tree = kwargs["tree"]

        component_name, component_version = tree.component(product_id)
        score = kwargs["scores_by_product"].get(product_id)
        remediations = kwargs["remediations_by_product"].get(product_id, [])

        title = (vulnerability.get("title") or "").strip()
        display_title = f"{component_name}:{component_version} | {identifier}" if component_version \
            else f"{component_name} | {identifier}"

        finding = Finding(
            title=display_title,
            test=kwargs["test"],
            description=self._description(
                vulnerability, identifier, bucket, component_name, component_version,
                title, kwargs["advisory_title"], kwargs["publisher"], score,
            ),
            severity=self._severity(score),
            mitigation=self._mitigation(remediations, bucket),
            references=self._references(vulnerability),
            component_name=component_name,
            component_version=component_version,
            static_finding=True,
            dynamic_finding=False,
            vuln_id_from_tool=identifier,
            unique_id_from_tool=f"{product_id}|{identifier}",
        )
        finding.unsaved_vulnerability_ids = self._vulnerability_ids(vulnerability, identifier)

        if cwe := self._cwe(vulnerability):
            finding.cwe = cwe

        if score and (vector := score.get("vectorString")):
            finding.cvssv3 = vector
        if score and isinstance(score.get("baseScore"), (int, float)):
            finding.cvssv3_score = score["baseScore"]

        if kwargs["report_date"]:
            finding.date = kwargs["report_date"]

        self._apply_status(finding, bucket)

        return finding

    def _apply_status(self, finding, bucket):
        """
        Translate the product_status bucket into the finding's state.

        ★ known_not_affected must never be active: the advisory explicitly states the product is not
        exposed, and importing that as work would invert the vendor's message.
        """
        if bucket == STATUS_KNOWN_NOT_AFFECTED:
            finding.active = False
            finding.false_p = True
            return

        if bucket in FIXED_BUCKETS:
            finding.active = False
            finding.is_mitigated = True
            return

        if bucket == STATUS_UNDER_INVESTIGATION:
            finding.active = True
            finding.verified = False
            return

        # AFFECTED_BUCKETS, and any bucket a future revision adds. Defaulting an unknown bucket to
        # active is safer than silently suppressing a real exposure.
        finding.active = True

    # -- field mapping --------------------------------------------------------------------------------

    def _identifier(self, vulnerability):
        """Prefer the CVE; fall back to the advisory's own tracking id for an embargoed issue."""
        if cve := (vulnerability.get("cve") or "").strip():
            return cve
        for entry in vulnerability.get("ids", []) or []:
            if isinstance(entry, dict) and (text := (entry.get("text") or "").strip()):
                return text
        return (vulnerability.get("title") or "").strip()

    def _vulnerability_ids(self, vulnerability, identifier):
        identifiers = [identifier] if identifier else []
        for entry in vulnerability.get("ids", []) or []:
            if not isinstance(entry, dict):
                continue
            text = (entry.get("text") or "").strip()
            if text and text not in identifiers:
                identifiers.append(text)
        return identifiers

    def _cwe(self, vulnerability):
        """Return the numeric CWE id, or 0. CSAF writes it as the string "CWE-79"."""
        cwe = vulnerability.get("cwe") or {}
        raw = (cwe.get("id") or "").strip().upper()
        raw = raw.removeprefix("CWE-")
        try:
            return int(raw)
        except ValueError:
            return 0

    def _scores_by_product(self, vulnerability):
        """
        Index the CVSS v3 scores by product id.

        A CSAF `scores[]` entry applies to a listed set of products, so the same advisory can score the
        same CVE differently per product. Later entries win, matching document order.
        """
        by_product = {}
        for score in vulnerability.get("scores", []) or []:
            if not isinstance(score, dict):
                continue
            # cvss_v3 covers both 3.0 and 3.1; some producers also emit cvss_v4.
            cvss = score.get("cvss_v3") or score.get("cvss_v31") or score.get("cvss_v30")
            if not isinstance(cvss, dict):
                continue
            for product_id in score.get("products", []) or []:
                by_product[str(product_id).strip()] = cvss
        return by_product

    def _remediations_by_product(self, vulnerability):
        by_product = {}
        for remediation in vulnerability.get("remediations", []) or []:
            if not isinstance(remediation, dict):
                continue
            for product_id in remediation.get("product_ids", []) or []:
                by_product.setdefault(str(product_id).strip(), []).append(remediation)
        return by_product

    def _severity(self, score):
        """
        Map the CVSS v3 baseSeverity to a DefectDojo severity.

        When the advisory gives a score but no qualitative rating, the standard CVSS v3 bands are used.
        When it gives neither, Medium is the fallback rather than Info: a published vendor advisory is
        not informational, and Info would hide it behind a minimum-severity setting.
        """
        if not score:
            return "Medium"

        rating = str(score.get("baseSeverity") or "").strip().upper()
        if rating in CVSS3_SEVERITY:
            return CVSS3_SEVERITY[rating]

        base = score.get("baseScore")
        if isinstance(base, (int, float)):
            if base >= 9.0:
                return "Critical"
            if base >= 7.0:
                return "High"
            if base >= 4.0:
                return "Medium"
            if base > 0:
                return "Low"
            return "Info"

        return "Medium"

    def _mitigation(self, remediations, bucket):
        if not remediations:
            if bucket in FIXED_BUCKETS:
                return "The advisory lists this product as fixed."
            if bucket == STATUS_KNOWN_NOT_AFFECTED:
                return "No action required. The advisory states this product is not affected."
            return ""

        lines = []
        for remediation in remediations:
            category = (remediation.get("category") or "").strip()
            details = (remediation.get("details") or "").strip()
            header = f"**{category}**" if category else "**remediation**"
            lines.append(f"{header}: {details}" if details else header)
            if url := (remediation.get("url") or "").strip():
                lines.append(f"  {url}")
            if restart := (remediation.get("restart_required") or {}).get("category"):
                lines.append(f"  Restart required: {restart}")
        return "\n".join(lines)

    def _description(self, vulnerability, identifier, bucket, component_name, component_version,
                     title, advisory_title, publisher, score):
        component = component_name + (f" {component_version}" if component_version else "")
        parts = [f"**{identifier}** — product status **{bucket}** for **{component}**."]

        if bucket == STATUS_KNOWN_NOT_AFFECTED:
            parts.append(
                "**This finding is imported inactive.** The advisory explicitly lists this product as "
                "*known_not_affected*, so it suppresses rather than reports.",
            )

        if title:
            parts.append(f"**Vulnerability:** {title}")

        for note in vulnerability.get("notes", []) or []:
            if not isinstance(note, dict):
                continue
            category = (note.get("category") or "").strip()
            text = (note.get("text") or "").strip()
            if not text:
                continue
            if category in {"description", "summary", "details", "general"}:
                parts.append(text)
            else:
                label = (note.get("title") or category or "note").strip()
                parts.append(f"**{label}:** {text}")

        if score:
            if vector := (score.get("vectorString") or "").strip():
                parts.append(f"**CVSS vector:** {vector}")
            if isinstance(score.get("baseScore"), (int, float)):
                parts.append(f"**CVSS base score:** {score['baseScore']}")

        if advisory_title:
            parts.append(f"**Advisory:** {advisory_title}")
        if publisher:
            parts.append(f"**Publisher:** {publisher}")

        return "\n\n".join(parts)

    def _references(self, vulnerability):
        lines = []
        for reference in vulnerability.get("references", []) or []:
            if not isinstance(reference, dict):
                continue
            url = (reference.get("url") or "").strip()
            if not url:
                continue
            summary = (reference.get("summary") or "").strip()
            lines.append(f"**{summary}:** {url}" if summary else url)
        return "\n".join(lines)
