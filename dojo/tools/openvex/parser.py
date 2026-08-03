import json

import dateutil.parser

from dojo.models import Finding

# OpenVEX statement statuses (https://github.com/openvex/spec).
STATUS_NOT_AFFECTED = "not_affected"
STATUS_AFFECTED = "affected"
STATUS_FIXED = "fixed"
STATUS_UNDER_INVESTIGATION = "under_investigation"

# The five justifications the spec allows on a not_affected statement. Each says something different
# about WHY the product is not affected, so each maps to a different DefectDojo disposition.
JUSTIFICATION_COMPONENT_NOT_PRESENT = "component_not_present"
JUSTIFICATION_VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
JUSTIFICATION_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
JUSTIFICATION_CANNOT_BE_CONTROLLED = "vulnerable_code_cannot_be_controlled_by_adversary"
JUSTIFICATION_INLINE_MITIGATIONS = "inline_mitigations_already_exist"

JUSTIFICATION_TEXT = {
    JUSTIFICATION_COMPONENT_NOT_PRESENT:
        "The component named in the vulnerability is not present in the product.",
    JUSTIFICATION_VULNERABLE_CODE_NOT_PRESENT:
        "The vulnerable code is not present in the product.",
    JUSTIFICATION_NOT_IN_EXECUTE_PATH:
        "The vulnerable code is present but can never be executed.",
    JUSTIFICATION_CANNOT_BE_CONTROLLED:
        "The vulnerable code is present and reachable, but an adversary cannot control the inputs "
        "required to exploit it.",
    JUSTIFICATION_INLINE_MITIGATIONS:
        "A mitigation is already built into the product, so the vulnerability cannot be exploited.",
}


class OpenVEXParser:

    """
    OpenVEX is an implementation of the Vulnerability Exploitability eXchange (VEX) model: a document
    in which a producer states whether their product is actually affected by a known vulnerability.

    ★ VEX IS A SUPPRESSION SIGNAL, NOT A FINDING SOURCE.

    The whole purpose of a VEX document is to tell a consumer which vulnerabilities they can stop
    worrying about. A `not_affected` statement therefore NEVER produces an active finding. Importing
    one as active would invert the document's meaning and make DefectDojo worse than not reading it at
    all - a producer's "you are safe from this" would arrive as new work.

    Status handling, in full:

    | status               | active | disposition                                     |
    |----------------------|--------|-------------------------------------------------|
    | not_affected         | no     | out_of_scope / false_p / mitigated, by justification |
    | fixed                | no     | is_mitigated                                    |
    | affected             | YES    | active - the producer asserts real exposure     |
    | under_investigation  | YES    | active, Info severity, flagged as unconfirmed   |

    `affected` is deliberately the one status that becomes an active finding: it is the producer
    explicitly stating their product IS exposed, usually with an action_statement describing what the
    consumer must do. Suppressing that would lose the only actionable statement VEX carries.

    https://openvex.dev/
    """

    def get_scan_types(self):
        return ["OpenVEX Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "OpenVEX Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import OpenVEX documents. VEX is a suppression signal: not_affected and fixed statements "
            "are imported as inactive so they suppress matching findings, and only 'affected' "
            "statements create active findings."
        )

    def get_findings(self, file, test):
        data = json.load(file)
        if not isinstance(data, dict):
            msg = "This OpenVEX file is not an object; expected an OpenVEX document."
            raise TypeError(msg)

        document_timestamp = self._parse_date(data.get("timestamp"))
        author = (data.get("author") or "").strip()

        findings = {}
        for statement in data.get("statements", []):
            if not isinstance(statement, dict):
                continue
            for finding in self._statement_findings(statement, data, author, document_timestamp, test):
                findings.setdefault(finding.unique_id_from_tool, finding)

        return list(findings.values())

    # -- statement handling ---------------------------------------------------------------------------

    def _statement_findings(self, statement, data, author, document_timestamp, test):
        vulnerability_id = self._vulnerability_id(statement)
        if not vulnerability_id:
            return

        status = (statement.get("status") or "").strip().lower()
        if not status:
            return

        timestamp = self._parse_date(statement.get("timestamp")) or document_timestamp

        # A statement can name several products; each is a separate finding so a per-product
        # suppression does not silently suppress a sibling product too.
        for product in self._products(statement):
            yield self._build_finding(
                statement=statement,
                data=data,
                author=author,
                timestamp=timestamp,
                test=test,
                vulnerability_id=vulnerability_id,
                status=status,
                product=product,
            )

    def _build_finding(self, *, statement, data, author, timestamp, test, vulnerability_id, status, product):
        component_name, component_version = self._split_product(product)

        finding = Finding(
            title=f"{component_name}:{component_version} | {vulnerability_id}"
            if component_version
            else f"{component_name} | {vulnerability_id}",
            test=test,
            description=self._description(statement, data, author, vulnerability_id, status, product),
            severity=self._severity(status),
            mitigation=self._mitigation(statement, status),
            references=self._references(data, statement),
            component_name=component_name,
            component_version=component_version,
            static_finding=True,
            dynamic_finding=False,
            vuln_id_from_tool=vulnerability_id,
            unique_id_from_tool=f"{product}|{vulnerability_id}",
        )
        finding.unsaved_vulnerability_ids = self._vulnerability_ids(statement)

        if timestamp:
            finding.date = timestamp

        self._apply_status(finding, status, statement)

        return finding

    def _apply_status(self, finding, status, statement):
        """
        Translate the VEX status into DefectDojo's disposition fields.

        This is the security-critical part of the parser. Everything except `affected` and
        `under_investigation` must come out inactive.
        """
        if status == STATUS_NOT_AFFECTED:
            finding.active = False
            self._apply_not_affected_justification(finding, statement)
            return

        if status == STATUS_FIXED:
            finding.active = False
            finding.is_mitigated = True
            return

        if status == STATUS_UNDER_INVESTIGATION:
            # The producer has not decided yet. Active so it stays visible, but not presented as a
            # confirmed weakness.
            finding.active = True
            finding.verified = False
            return

        # STATUS_AFFECTED, and any status a future spec revision adds. Leaving an unrecognised status
        # active is the safe default: a new status that this parser does not understand must not
        # silently suppress a real vulnerability.
        finding.active = True

    def _apply_not_affected_justification(self, finding, statement):
        """
        Choose the disposition for a not_affected statement from its justification.

        The justifications say materially different things, and DefectDojo has distinct fields that
        match them, so collapsing all five into one disposition would throw away information the
        producer took the trouble to state.
        """
        justification = (statement.get("justification") or "").strip().lower()

        if justification == JUSTIFICATION_INLINE_MITIGATIONS:
            # A real mitigation exists in the product.
            finding.is_mitigated = True
        elif justification in {
            JUSTIFICATION_VULNERABLE_CODE_NOT_PRESENT,
            JUSTIFICATION_NOT_IN_EXECUTE_PATH,
            JUSTIFICATION_CANNOT_BE_CONTROLLED,
        }:
            # The scanner's match does not correspond to real exposure: a false positive.
            finding.false_p = True
        else:
            # component_not_present, or no justification at all. The finding does not apply to this
            # product, which is what out_of_scope means; it is also the conservative default for a
            # justification this parser does not recognise.
            finding.out_of_scope = True

    # -- field mapping --------------------------------------------------------------------------------

    def _severity(self, status):
        """
        VEX carries no severity: it states exploitability, not impact.

        `affected` is Medium so a producer-asserted exposure is not filtered out of sight by a
        minimum-severity setting. Everything else is Info, because those findings exist to suppress,
        not to be worked - ranking them would put suppressed rows in front of real ones.
        """
        if status == STATUS_AFFECTED:
            return "Medium"
        return "Info"

    def _mitigation(self, statement, status):
        action = (statement.get("action_statement") or "").strip()
        if status == STATUS_AFFECTED and action:
            return action
        if status == STATUS_FIXED:
            return "The producer reports this vulnerability as fixed in this product version."
        if status == STATUS_NOT_AFFECTED:
            return (
                "No action required. The producer states this product is not affected; see the "
                "justification in the description."
            )
        if status == STATUS_UNDER_INVESTIGATION:
            return "No action yet. The producer is still investigating whether this product is affected."
        return action

    def _description(self, statement, data, author, vulnerability_id, status, product):
        parts = [
            f"OpenVEX statement: **{vulnerability_id}** is **{status}** for `{product}`.",
        ]

        if status == STATUS_NOT_AFFECTED:
            parts.append(
                "**This finding is imported inactive.** A VEX `not_affected` statement is the "
                "producer asserting the product is NOT exploitable, so it suppresses rather than "
                "reports.",
            )
            justification = (statement.get("justification") or "").strip().lower()
            if justification:
                explanation = JUSTIFICATION_TEXT.get(justification, "")
                line = f"**Justification:** `{justification}`"
                if explanation:
                    line += f" - {explanation}"
                parts.append(line)
            else:
                parts.append(
                    "**Justification:** none supplied. The OpenVEX specification requires a "
                    "justification on a not_affected statement, so this document is incomplete.",
                )

        if impact := (statement.get("impact_statement") or "").strip():
            parts.append(f"**Impact statement:** {impact}")

        if action := (statement.get("action_statement") or "").strip():
            parts.append(f"**Action statement:** {action}")

        if status == STATUS_UNDER_INVESTIGATION:
            parts.append(
                "The producer has not yet determined whether this product is affected. Treat as "
                "unconfirmed.",
            )

        if author:
            parts.append(f"**Statement author:** {author}")

        if document_id := (data.get("@id") or "").strip():
            parts.append(f"**VEX document:** {document_id}")

        return "\n\n".join(parts)

    def _references(self, data, statement):
        lines = []
        if context := (data.get("@context") or "").strip():
            lines.append(f"**OpenVEX context:** {context}")
        vulnerability = statement.get("vulnerability")
        if isinstance(vulnerability, dict):
            if identifier := (vulnerability.get("@id") or "").strip():
                lines.append(f"**Vulnerability:** {identifier}")
        return "\n".join(lines)

    # -- shape helpers --------------------------------------------------------------------------------

    def _vulnerability_id(self, statement):
        """
        Return the statement's vulnerability name.

        OpenVEX v0.0.1 used a bare string for `vulnerability`; v0.2.0 uses an object with `name`,
        `@id` and `aliases`. Both shapes are accepted so older documents still import.
        """
        vulnerability = statement.get("vulnerability")
        if isinstance(vulnerability, str):
            return vulnerability.strip()
        if isinstance(vulnerability, dict):
            name = (vulnerability.get("name") or "").strip()
            if name:
                return name
            return (vulnerability.get("@id") or "").strip()
        return ""

    def _vulnerability_ids(self, statement):
        """Return the vulnerability name plus any aliases, deduplicated and order-preserving."""
        identifiers = []
        primary = self._vulnerability_id(statement)
        if primary:
            identifiers.append(primary)

        vulnerability = statement.get("vulnerability")
        if isinstance(vulnerability, dict):
            for raw_alias in vulnerability.get("aliases", []) or []:
                alias = str(raw_alias).strip()
                if alias and alias not in identifiers:
                    identifiers.append(alias)

        return identifiers

    def _products(self, statement):
        """
        Return the statement's product identifiers.

        As with `vulnerability`, v0.0.1 used bare strings and v0.2.0 uses objects keyed by `@id`.
        """
        products = []
        for product in statement.get("products", []) or []:
            if isinstance(product, str):
                identifier = product.strip()
            elif isinstance(product, dict):
                identifier = (product.get("@id") or "").strip()
            else:
                continue
            if identifier and identifier not in products:
                products.append(identifier)
        return products

    def _split_product(self, product):
        """
        Split a product identifier into a component name and version.

        Product identifiers are usually Package URLs, where the version follows an '@'. Anything that
        is not a PURL is used verbatim as the component name.
        """
        identifier = product
        # Drop PURL qualifiers and subpath before looking for the version separator.
        for separator in ("?", "#"):
            identifier = identifier.split(separator, 1)[0]

        if "@" in identifier:
            name, _, version = identifier.rpartition("@")
            return name, version
        return identifier, ""

    def _parse_date(self, value):
        if not value:
            return None
        try:
            return dateutil.parser.parse(str(value))
        except (ValueError, OverflowError, dateutil.parser.ParserError):
            return None
