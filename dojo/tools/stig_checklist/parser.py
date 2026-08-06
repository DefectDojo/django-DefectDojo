"""
Parser for DISA STIG Viewer checklists.

Two interchangeable formats are accepted, told apart by content rather than by file name so a
renamed export still imports:

- `.ckl`  - STIG Viewer 2.x, XML rooted at `<CHECKLIST>`.
- `.cklb` - STIG Viewer 3.x, JSON.

Both readers build the same intermediate `ChecklistItem` records, so the two formats produce
identical findings for identical content (locked down by a parity unit test).

Identity: the V-number (`Vuln_Num` / `group_id`) is the stable per-rule identifier. `Rule_ID`
carries a revision suffix (`SV-257777r925318_rule`) that changes with every STIG release, so it is
recorded for display only and never participates in identity.

REFERENCES FORMAT IS A CROSS-REPO CONTRACT. Every CCI is written as a bare `CCI-NNNNNN` token on
its own line. DefectDojo Pro's federal compliance pack reads those tokens back out of
`Finding.references` to crosswalk each checklist item onto its NIST 800-53 controls. Reformatting
these lines breaks that mapping.
"""

import json
import logging
from dataclasses import dataclass, field

from defusedxml.ElementTree import ParseError, fromstring
from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

logger = logging.getLogger(__name__)

SCAN_TYPE = "DISA STIG Checklist"

# STIG severity is the rule's DISA category. Anything else (including an empty value, which real
# checklists do contain) is imported as Info rather than dropped: the item still has to be tracked.
SEVERITY_MAP = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
DEFAULT_SEVERITY = "Info"
# DISA category of the rule, kept in Impact so it survives an assessor severity override.
CATEGORY_MAP = {
    "high": "CAT I",
    "medium": "CAT II",
    "low": "CAT III",
}

# Checklist status -> finding flags. `.ckl` uses CamelCase ("NotAFinding"), `.cklb` uses snake_case
# ("not_a_finding"), so statuses are normalised before lookup.
#
# NotAFinding and Not_Applicable deliberately carry is_mitigated/out_of_scope rather than only
# active=False: on reimport an incoming finding that is merely inactive is a no-op, while
# is_mitigated closes the existing finding and out_of_scope copies the flag across.
STATUS_FLAGS = {
    "open": {"active": True, "verified": True},
    "notreviewed": {"active": True, "verified": False},
    "notafinding": {"active": False, "verified": False, "is_mitigated": True},
    "notapplicable": {"active": False, "verified": False, "out_of_scope": True},
}
DEFAULT_STATUS = "notreviewed"

# CKL <STIG_INFO> keys this parser uses, out of the ~11 STIG Viewer writes.
CKL_STIG_INFO_KEYS = {"title", "stigid", "version", "releaseinfo"}


@dataclass
class AssetInfo:

    """The single host a checklist describes, from CKL <ASSET> or CKLB target_data."""

    host_name: str = ""
    fqdn: str = ""
    ip: str = ""

    @property
    def host(self) -> str:
        """The most specific identifier the checklist recorded. Blank when the asset is un-keyed."""
        return self.fqdn or self.host_name or self.ip


@dataclass
class ChecklistItem:

    """One assessed rule, normalised across the two checklist formats."""

    group_id: str = ""
    rule_id: str = ""
    rule_version: str = ""
    rule_title: str = ""
    group_title: str = ""
    severity: str = ""
    severity_override: str = ""
    severity_justification: str = ""
    status: str = ""
    discussion: str = ""
    check_content: str = ""
    fix_text: str = ""
    finding_details: str = ""
    comments: str = ""
    ccis: list[str] = field(default_factory=list)
    stig_title: str = ""
    stig_id: str = ""
    stig_version: str = ""
    stig_release: str = ""

    def add_cci(self, cci: str) -> None:
        """CKL repeats a CCI_REF block per reference; keep first-seen order and drop repeats."""
        cci = (cci or "").strip().upper()
        if cci and cci not in self.ccis:
            self.ccis.append(cci)


class StigChecklistParser:

    """Parses DISA STIG Viewer checklists in both the `.ckl` (XML) and `.cklb` (JSON) formats."""

    def get_scan_types(self):
        return [SCAN_TYPE]

    def get_label_for_scan_types(self, scan_type):
        return SCAN_TYPE

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a DISA STIG Viewer checklist: .ckl (STIG Viewer 2.x, XML) or .cklb "
            "(STIG Viewer 3.x, JSON). Open items are imported as active findings."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the STIG Checklist Parser.

        Fields:
        - title: V-number and rule title.
        - severity: the rule's DISA category, or the assessor's severity override where present.
        - severity_justification: the assessor's reason for a severity override.
        - impact: the rule's DISA category (CAT I/II/III), which an override does not change.
        - description: group, rule version, rule id, checklist, discussion, finding details, comments.
        - steps_to_reproduce: the rule's check content, i.e. how to assess the item.
        - mitigation: the rule's fix text.
        - references: the checklist the rule came from and every CCI it cites.
        - component_name: the STIG the rule belongs to (for example RHEL_9_STIG).
        - component_version: the STIG version and release.
        - vuln_id_from_tool: the V-number, which is stable across STIG releases.
        - unique_id_from_tool: host-qualified V-number, so one rule on two hosts stays two findings.
        - active / verified / is_mitigated / out_of_scope: mapped from the checklist status.
        - dynamic_finding: True - a checklist records an assessment of a running host.

        NOTE: the host is reported through unsaved_locations (or unsaved_endpoints), and Rule_ID is
        recorded in the description only, because its revision suffix changes every STIG release.
        """
        return [
            "title",
            "severity",
            "severity_justification",
            "impact",
            "description",
            "steps_to_reproduce",
            "mitigation",
            "references",
            "component_name",
            "component_version",
            "vuln_id_from_tool",
            "unique_id_from_tool",
            "active",
            "verified",
            "is_mitigated",
            "out_of_scope",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the STIG Checklist Parser.

        Fields:
        - vuln_id_from_tool: the V-number.
        - endpoints: the assessed host.

        NOTE: matching itself uses unique_id_from_tool, which already qualifies the V-number with
        the host. Neither severity (assessors override it) nor the description (it holds per-scan
        finding details) may take part, and Rule_ID is revision-suffixed.
        """
        return ["vuln_id_from_tool", "endpoints"]

    def get_findings(self, file, test):
        content = file.read()
        raw = content.encode("utf-8") if isinstance(content, str) else content
        asset, items = self.parse_checklist(raw)

        findings = {}
        for item in items:
            if not item.group_id:
                logger.warning("Skipping a STIG checklist item with no V-number; it has no identity.")
                continue
            finding = self.build_finding(item, asset, test)
            # A well-formed checklist assesses each rule once. Collapse repeats rather than
            # importing findings that would immediately deduplicate against each other.
            if finding.unique_id_from_tool in findings:
                logger.debug("STIG checklist repeats %s; keeping the first occurrence.", item.group_id)
                continue
            findings[finding.unique_id_from_tool] = finding
        return list(findings.values())

    def parse_checklist(self, raw: bytes) -> tuple[AssetInfo, list[ChecklistItem]]:
        """Detect the checklist format from its content and dispatch to the matching reader."""
        # Skip a UTF-8 BOM and any leading whitespace so the first meaningful byte decides.
        head = raw.lstrip(b"\xef\xbb\xbf \t\r\n")
        if head.startswith(b"{"):
            return self.parse_cklb(self.load_json(raw))
        if head.startswith(b"<"):
            return self.parse_ckl(self.load_xml(raw))
        msg = (
            "This does not look like a DISA STIG Viewer checklist. Expected either a .ckl file "
            "(XML with a CHECKLIST root element) or a .cklb file (JSON)."
        )
        raise ValueError(msg)

    def load_json(self, raw: bytes) -> dict:
        """
        Only reached once the sniff has seen a leading `{`, which means the document either fails
        to parse or parses as an object - so there is no non-object case left to reject here.
        """
        try:
            # utf-8-sig tolerates the BOM some checklist writers emit.
            return json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            msg = f"This .cklb checklist is not valid JSON: {exc}"
            raise ValueError(msg) from exc

    def load_xml(self, raw: bytes):
        # Parsed from bytes on purpose: expat then honours the encoding the XML prolog declares,
        # which for STIG Viewer exports is not always UTF-8.
        try:
            root = fromstring(raw)
        except ParseError as exc:
            msg = f"This .ckl checklist is not valid XML: {exc}"
            raise ValueError(msg) from exc
        if root.tag != "CHECKLIST":
            msg = (
                f"Expected a STIG Viewer checklist rooted at CHECKLIST, found '{root.tag}'. "
                "XCCDF benchmark results are imported with the Openscap parser instead."
            )
            raise ValueError(msg)
        return root

    # --- .ckl (STIG Viewer 2.x, XML) ---------------------------------------------------------

    def parse_ckl(self, root) -> tuple[AssetInfo, list[ChecklistItem]]:
        asset = AssetInfo(
            host_name=self.text(root.findtext("./ASSET/HOST_NAME")),
            fqdn=self.text(root.findtext("./ASSET/HOST_FQDN")),
            ip=self.text(root.findtext("./ASSET/HOST_IP")),
        )
        items = []
        # A single checklist can hold several iSTIG blocks: one host assessed against several STIGs.
        for istig in root.findall("./STIGS/iSTIG"):
            stig_info = self.ckl_stig_info(istig)
            items.extend(self.ckl_item(vuln, stig_info) for vuln in istig.findall("./VULN"))
        return asset, items

    def ckl_stig_info(self, istig) -> dict[str, str]:
        """Read the <STIG_INFO> SID_NAME/SID_DATA pairs describing which STIG this block covers."""
        info = {}
        for si_data in istig.findall("./STIG_INFO/SI_DATA"):
            name = self.text(si_data.findtext("./SID_NAME")).lower()
            if name in CKL_STIG_INFO_KEYS and name not in info:
                info[name] = self.text(si_data.findtext("./SID_DATA"))
        return info

    def ckl_item(self, vuln, stig_info: dict[str, str]) -> ChecklistItem:
        item = ChecklistItem(
            status=self.text(vuln.findtext("./STATUS")),
            finding_details=self.text(vuln.findtext("./FINDING_DETAILS")),
            comments=self.text(vuln.findtext("./COMMENTS")),
            severity_override=self.text(vuln.findtext("./SEVERITY_OVERRIDE")),
            severity_justification=self.text(vuln.findtext("./SEVERITY_JUSTIFICATION")),
            stig_title=stig_info.get("title", ""),
            stig_id=stig_info.get("stigid", ""),
            stig_version=stig_info.get("version", ""),
            stig_release=stig_info.get("releaseinfo", ""),
        )
        # Rule metadata arrives as a flat list of attribute/value pairs, with CCI_REF repeated once
        # per reference.
        attributes = {
            "Vuln_Num": "group_id",
            "Rule_ID": "rule_id",
            "Rule_Ver": "rule_version",
            "Rule_Title": "rule_title",
            "Group_Title": "group_title",
            "Severity": "severity",
            "Vuln_Discuss": "discussion",
            "Check_Content": "check_content",
            "Fix_Text": "fix_text",
        }
        for stig_data in vuln.findall("./STIG_DATA"):
            name = self.text(stig_data.findtext("./VULN_ATTRIBUTE"))
            value = self.text(stig_data.findtext("./ATTRIBUTE_DATA"))
            if name == "CCI_REF":
                item.add_cci(value)
            elif (attribute := attributes.get(name)) and value and not getattr(item, attribute):
                setattr(item, attribute, value)
        return item

    # --- .cklb (STIG Viewer 3.x, JSON) -------------------------------------------------------

    def parse_cklb(self, data: dict) -> tuple[AssetInfo, list[ChecklistItem]]:
        target = data.get("target_data") or {}
        asset = AssetInfo(
            host_name=self.text(target.get("host_name")),
            fqdn=self.text(target.get("fqdn")),
            ip=self.text(target.get("ip_address")),
        )
        items = []
        for stig in data.get("stigs") or []:
            if not isinstance(stig, dict):
                continue
            items.extend(
                self.cklb_item(rule, stig)
                for rule in stig.get("rules") or []
                if isinstance(rule, dict)
            )
        return asset, items

    def cklb_item(self, rule: dict, stig: dict) -> ChecklistItem:
        override = (rule.get("overrides") or {}).get("severity") or {}
        item = ChecklistItem(
            group_id=self.text(rule.get("group_id")),
            rule_id=self.text(rule.get("rule_id")),
            rule_version=self.text(rule.get("rule_version")),
            rule_title=self.text(rule.get("rule_title")),
            group_title=self.text(rule.get("group_title")),
            severity=self.text(rule.get("severity")),
            severity_override=self.text(override.get("severity")),
            # STIG Viewer writes "reason"; some other checklist writers use "justification".
            severity_justification=self.text(override.get("reason") or override.get("justification")),
            status=self.text(rule.get("status")),
            discussion=self.text(rule.get("discussion")),
            check_content=self.text(rule.get("check_content")),
            fix_text=self.text(rule.get("fix_text")),
            finding_details=self.text(rule.get("finding_details")),
            comments=self.text(rule.get("comments")),
            stig_title=self.text(stig.get("display_name") or stig.get("stig_name")),
            stig_id=self.text(stig.get("stig_id")),
            stig_version=self.text(stig.get("version")),
            stig_release=self.text(stig.get("release_info")),
        )
        for cci in rule.get("ccis") or []:
            item.add_cci(cci if isinstance(cci, str) else "")
        return item

    # --- checklist item -> Finding ------------------------------------------------------------

    def build_finding(self, item: ChecklistItem, asset: AssetInfo, test) -> Finding:
        severity_key = (item.severity_override or item.severity).lower()
        finding = Finding(
            test=test,
            title=f"{item.group_id} - {item.rule_title}".strip(" -")[:511],
            severity=SEVERITY_MAP.get(severity_key, DEFAULT_SEVERITY),
            severity_justification=self.build_severity_justification(item) or None,
            # The DISA category belongs to the rule, so an assessor override does not move it.
            impact=CATEGORY_MAP.get(item.severity.lower()) or None,
            description=self.build_description(item),
            steps_to_reproduce=item.check_content or None,
            mitigation=item.fix_text or None,
            references=self.build_references(item) or None,
            component_name=(item.stig_id or item.stig_title)[:500] or None,
            component_version=self.build_component_version(item)[:100] or None,
            vuln_id_from_tool=item.group_id[:500],
            unique_id_from_tool=self.build_unique_id(item, asset),
            # A checklist records an assessment of a running host, not a code review.
            dynamic_finding=True,
            static_finding=False,
            **self.status_flags(item),
        )
        finding.unsaved_tags = ["stig"]
        self.attach_host(finding, asset)
        return finding

    def status_flags(self, item: ChecklistItem) -> dict[str, bool]:
        key = item.status.lower().replace("_", "").replace(" ", "")
        if key not in STATUS_FLAGS:
            logger.warning(
                "Unrecognised STIG checklist status '%s' on %s; treating it as Not_Reviewed.",
                item.status, item.group_id,
            )
            key = DEFAULT_STATUS
        return dict(STATUS_FLAGS[key])

    def build_unique_id(self, item: ChecklistItem, asset: AssetInfo) -> str:
        """
        Qualify the V-number with the host.

        One rule assessed on two hosts has to stay two findings, and reimport matches on this id
        without ever comparing endpoints. A checklist with no host recorded falls back to the bare
        V-number, so two un-keyed assets in one product would share an identity - key the asset in
        STIG Viewer to avoid that.
        """
        host = asset.host.lower()
        return (f"{host}/{item.group_id}" if host else item.group_id)[:500]

    def build_severity_justification(self, item: ChecklistItem) -> str:
        if not item.severity_override:
            return item.severity_justification
        original = item.severity or "unspecified"
        note = f"Severity overridden from '{original}' to '{item.severity_override}' by the assessor."
        return f"{note}\n{item.severity_justification}" if item.severity_justification else note

    def build_description(self, item: ChecklistItem) -> str:
        sections = [
            ("Group", item.group_title),
            ("Rule Version (STIG-ID)", item.rule_version),
            # Display only: the revision suffix changes with every STIG release.
            ("Rule ID", item.rule_id),
            ("Checklist", item.stig_title),
            ("Discussion", item.discussion),
            ("Finding Details", item.finding_details),
            ("Comments", item.comments),
        ]
        return "\n".join(f"**{label}:** {value}" for label, value in sections if value)

    def build_references(self, item: ChecklistItem) -> str:
        """
        Record the source checklist and every CCI the rule cites.

        The bare `CCI-NNNNNN` lines are the contract described in this module's docstring: Pro reads
        them back to crosswalk the item onto its NIST 800-53 controls.
        """
        lines = []
        if stig := self.build_stig_reference(item):
            lines.append(f"**STIG:** {stig}")
        if item.rule_id:
            rule = f"{item.rule_id} ({item.rule_version})" if item.rule_version else item.rule_id
            lines.append(f"**Rule:** {rule}")
        lines.extend(item.ccis)
        return "\n".join(lines)

    def build_stig_reference(self, item: ChecklistItem) -> str:
        """Name the source checklist the way DISA's own STIGRef attribute does."""
        reference = item.stig_title
        if item.stig_version:
            reference = f"{reference} :: Version {item.stig_version}" if reference else f"Version {item.stig_version}"
        if item.stig_release:
            reference = f"{reference}, {item.stig_release}" if reference else item.stig_release
        return reference

    def build_component_version(self, item: ChecklistItem) -> str:
        """Combine the STIG version with the release number STIG Viewer writes as free text."""
        if not item.stig_version:
            return ""
        release = ""
        for token in item.stig_release.replace(":", " ").split():
            if release == "pending":
                release = token
                break
            if token.lower() == "release":
                release = "pending"
        if release and release != "pending":
            return f"V{item.stig_version}R{release}"
        return item.stig_version

    def attach_host(self, finding: Finding, asset: AssetInfo) -> None:
        """A checklist describes one host; an un-keyed checklist has none to report."""
        host = asset.host
        if settings.V3_FEATURE_LOCATIONS:
            finding.unsaved_locations = [LocationData.url(host=host)] if host else []
        else:
            # TODO: Delete this after the move to Locations
            finding.unsaved_endpoints = [Endpoint(host=host)] if host else []

    def text(self, value) -> str:
        return (value or "").strip() if isinstance(value, str) or value is None else str(value).strip()
