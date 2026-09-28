import json
from contextlib import suppress
from datetime import UTC, datetime, timedelta

from dojo.models import Finding

# How far ahead an upcoming expiry is still reported.
EXPIRING_SOON_WINDOW = timedelta(days=30)

# The smallest RSA key length considered acceptable.
MINIMUM_KEY_SIZE = 2048

# Hashes no longer considered collision resistant.
WEAK_HASHES = ("SHA1", "MD5", "MD2")

# The timestamp layouts the connector accepts, in its order.
TIMESTAMP_FORMATS = (
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d",
)


class VenafiParser:

    """
    Parses a CyberArk Certificate Manager (formerly Venafi) certificate inventory export.

    Mirrors pkg/tools/venafi/connector/finding_converter field for field so a file import and an API
    sync deduplicate against each other instead of producing two copies of everything.

    NEITHER EDITION RETURNS A COMPLIANCE VERDICT, so the posture rules are computed from each
    certificate's own attributes: expired, expiring within thirty days, a weak RSA key, a weak
    signature hash, and self-signed. One certificate therefore produces zero findings when it is
    healthy and several when it breaks several rules; see violations().

    A rule is SKIPPED when the attribute it needs is absent rather than guessed - a certificate with no
    recorded key size is not reported as weak.

    The two editions name their fields differently, so both are normalised the way the client does; see
    certificate().
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["CyberArk Certificate Manager Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "CyberArk Certificate Manager Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a CyberArk Certificate Manager (Venafi) certificate inventory export (JSON), from "
            "either the SaaS or the self-hosted edition. Certificate posture is computed from the "
            "certificate's own attributes. Matches the scan type used by the connector so file and API "
            "findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Venafi Parser.

        Mirrors the connector's Convert:
        - title: the posture problem, then the certificate's common name in brackets.
        - severity: fixed per rule - expired is Critical, a weak key or signature or an imminent
          expiry is High, self-signed is Medium.
        - description: what was found, then the certificate's names, issuer, key, signature, expiry
          and fingerprint.
        - mitigation: the remediation for that rule.
        - component_name: the certificate, named by common name or fingerprint.
        - vuln_id_from_tool: the rule that was broken.
        - unique_id_from_tool: "venafi-<fingerprint>-<rule>".
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "component_name",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "tags",
            "active",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Venafi Parser.

        Copied from the CyberArk Certificate Manager block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. The certificate is the component, so
        the same problem on two certificates stays two findings.
        """
        return ["title", "severity", "component_name"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        # Expiry is judged against NOW, exactly as the connector judges it against sync time. The same
        # file imported later therefore reports more expiries - which is correct, not a defect: a
        # certificate that has since lapsed really has lapsed.
        now = datetime.now(tz=UTC)

        findings = []
        for row in self.rows(data):
            certificate = self.certificate(row)
            findings.extend(
                self.build_finding(certificate, violation, test)
                for violation in self.violations(certificate, now)
            )
        return findings

    def rows(self, data):
        """
        Return the certificates in the export.

        The SaaS edition answers {"certificates": [...]}; the self-hosted one answers
        {"Certificates": [...]} - capitalised, as its whole API is. A bare array is accepted too.
        """
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            for key in ("certificates", "Certificates", "data", "results"):
                if isinstance(data.get(key), list):
                    return [row for row in data[key] if isinstance(row, dict)]

        msg = (
            "A CyberArk Certificate Manager export is a certificate inventory, a JSON object with a "
            f"'certificates' list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def certificate(self, row):
        """
        Normalise either edition's certificate into the shape the posture rules read.

        The SaaS edition sends subjectCN as a LIST and its SANs as a map keyed by type; the self-hosted
        one sends capitalised scalar fields. Reading only one edition's names would silently produce no
        findings against the other, because every rule's attribute would look absent.
        """
        if self.is_self_hosted(row):
            subject = str(row.get("Subject") or "")
            issuer = str(row.get("Issuer") or "")
            return {
                "id": self.first(row.get("Thumbprint"), row.get("Guid"), row.get("DN")),
                "common_name": self.first(row.get("CN"), subject, row.get("DN")),
                "sans": [],
                "issuer": issuer,
                "key_algorithm": str(row.get("KeyAlgorithm") or ""),
                "key_size": self.integer(row.get("KeySize")),
                "signature_algorithm": str(row.get("SignatureAlgorithm") or ""),
                "not_after": self.timestamp(row.get("ValidTo")),
                # The self-hosted edition has no self-signed flag, so it is inferred from the subject
                # matching the issuer - which is what self-signed means.
                "self_signed": bool(
                    subject.strip() and issuer.strip()
                    and subject.strip().casefold() == issuer.strip().casefold(),
                ),
            }

        return {
            "id": self.first(row.get("fingerprint"), row.get("id")),
            "common_name": self.first_of(row.get("subjectCN"), row.get("subjectDN")),
            "sans": self.flatten_sans(row.get("subjectAlternativeNamesByType")),
            "issuer": self.first_of(row.get("issuerCN"), row.get("issuerDN")),
            "key_algorithm": str(row.get("encryptionType") or ""),
            "key_size": self.integer(row.get("keyStrength")),
            "signature_algorithm": self.first(
                row.get("signatureHashAlgorithm"), row.get("signatureAlgorithm"),
            ),
            "not_after": self.timestamp(row.get("validityEnd")),
            "self_signed": bool(row.get("selfSigned")),
        }

    def is_self_hosted(self, row):
        """The self-hosted edition capitalises every field name, which is how the two are told apart."""
        return any(key in row for key in ("Thumbprint", "Guid", "DN", "CN", "ValidTo"))

    def violations(self, certificate, now):
        """
        Every posture rule the certificate breaks.

        A healthy certificate breaks none and produces no findings at all - which is the point of a
        computed check: the inventory is not itself a finding.
        """
        found = []

        if expiry := self.expiry_violation(certificate, now):
            found.append(expiry)

        key_size = certificate["key_size"]
        if 0 < key_size < MINIMUM_KEY_SIZE and self.is_rsa(certificate["key_algorithm"]):
            found.append({
                "kind": "weak-key",
                "title": f"Certificate uses a weak key ({key_size} bits)",
                "severity": "High",
                "detail": (
                    f"The key is {key_size} bits; at least {MINIMUM_KEY_SIZE} bits is required."
                ),
                "mitigation": (
                    f"Rekey the certificate with a key of at least {MINIMUM_KEY_SIZE} bits and "
                    "replace it on every deployment."
                ),
            })

        signature = certificate["signature_algorithm"]
        if self.is_weak_signature(signature):
            found.append({
                "kind": "weak-signature",
                "title": f"Certificate is signed with a weak algorithm ({signature})",
                "severity": "High",
                "detail": (
                    f"The signature algorithm is {signature}, which is no longer considered "
                    "collision resistant."
                ),
                "mitigation": "Reissue the certificate with a SHA-256 or stronger signature.",
            })

        if certificate["self_signed"]:
            found.append({
                "kind": "self-signed",
                "title": "Certificate is self-signed",
                "severity": "Medium",
                "detail": (
                    "The certificate is self-signed, so relying parties cannot validate it against a "
                    "trusted issuer."
                ),
                "mitigation": (
                    "Replace the certificate with one issued by a trusted certificate authority."
                ),
            })
        return found

    def expiry_violation(self, certificate, now):
        """
        An expired certificate, or one expiring within thirty days.

        A certificate with no recorded expiry is not reported either way - guessing would either raise
        a false alarm or hide a real lapse.
        """
        not_after = certificate["not_after"]
        if not_after is None:
            return None

        if not_after < now:
            return {
                "kind": "expired",
                "title": "Certificate has expired",
                "severity": "Critical",
                "detail": f"The certificate expired on {self.render(not_after)}.",
                "mitigation": "Renew the certificate and replace it on every deployment.",
            }

        if not_after < now + EXPIRING_SOON_WINDOW:
            days = int((not_after - now).total_seconds() // 3600 // 24)
            return {
                "kind": "expiring-soon",
                "title": "Certificate expires within 30 days",
                "severity": "High",
                "detail": (
                    f"The certificate expires on {self.render(not_after)} (in {days} days)."
                ),
                "mitigation": "Schedule renewal before the expiry date.",
            }
        return None

    def build_finding(self, certificate, violation, test):
        label = self.label(certificate)

        finding = Finding(
            test=test,
            title=f"{violation['title']} ({label})",
            severity=violation["severity"],
            description=self.describe(certificate, violation, label),
            mitigation=violation["mitigation"],
            component_name=label or None,
            unique_id_from_tool=f"venafi-{certificate['id']}-{violation['kind']}",
            vuln_id_from_tool=violation["kind"],
            # A certificate's posture is read from its attributes; nothing is exercised.
            static_finding=True,
            dynamic_finding=False,
            active=True,
        )
        finding.unsaved_tags = self.tags(certificate, violation)
        return finding

    def label(self, certificate):
        """The certificate's common name, falling back to its fingerprint."""
        if name := certificate["common_name"].strip():
            return name
        return certificate["id"]

    def describe(self, certificate, violation, label):
        lines = []

        def write(field, value):
            if str(value or "").strip():
                lines.append(f"**{field}:** {value}")

        write("Finding", violation["detail"])
        write("Common name", certificate["common_name"])
        write("Subject alternative names", ", ".join(certificate["sans"]))
        write("Issuer", certificate["issuer"])
        write("Key", self.key_label(certificate))
        write("Signature algorithm", certificate["signature_algorithm"])
        write("Expires", self.render(certificate["not_after"]))
        write("Fingerprint", certificate["id"])
        return "\n".join(lines).strip() or f"**Finding:** {label}"

    def key_label(self, certificate):
        """"RSA 2048 bits", or whichever half is known."""
        algorithm = certificate["key_algorithm"]
        size = certificate["key_size"]
        if algorithm and size > 0:
            return f"{algorithm} {size} bits"
        if size > 0:
            return f"{size} bits"
        return algorithm

    def tags(self, certificate, violation):
        """The rule that was broken and the key algorithm, for filtering."""
        tags = [violation["kind"]]
        if algorithm := certificate["key_algorithm"].strip():
            tags.append(algorithm)
        return tags

    def is_rsa(self, algorithm):
        """
        Whether the 2048-bit floor applies.

        An elliptic-curve key is much shorter by design, so applying the RSA floor to it would report
        every EC certificate as weak.
        """
        return "RSA" in algorithm.strip().upper()

    def is_weak_signature(self, algorithm):
        """
        Whether the signature uses a broken hash.

        Hyphens are stripped first so "SHA-1" and "SHA1" are both recognised.
        """
        normalised = algorithm.strip().upper().replace("-", "")
        if not normalised:
            return False
        return any(weak in normalised for weak in WEAK_HASHES)

    def timestamp(self, value):
        """
        The certificate's expiry, in whichever of the connector's layouts it arrives.

        A value with no timezone is read as UTC, so it can be compared with an aware "now" - the
        connector compares against a UTC instant for the same reason.
        """
        text = str(value or "").strip()
        if not text:
            return None
        for fmt in TIMESTAMP_FORMATS:
            with suppress(ValueError):
                parsed = datetime.strptime(text, fmt)
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        return None

    def render(self, moment):
        """RFC 3339 in UTC, as the connector renders it."""
        if moment is None:
            return ""
        return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    def flatten_sans(self, by_type):
        """
        Every subject alternative name, whatever type it was filed under.

        SORTED, unlike the connector: it iterates a Go map, whose order is randomised, so its own
        rendering of this line varies between syncs. Sorting keeps a file import stable and readable.
        The line is not part of the deduplication hash, so the two still match.
        """
        if not isinstance(by_type, dict):
            return []
        names = [
            str(value).strip()
            for values in by_type.values()
            if isinstance(values, list)
            for value in values
            if str(value or "").strip()
        ]
        return sorted(names)

    def first(self, *values):
        for value in values:
            if trimmed := str(value or "").strip():
                return trimmed
        return ""

    def first_of(self, listed, fallback):
        """The SaaS edition sends the common name and issuer as LISTS; the first entry is the name."""
        if isinstance(listed, list):
            for value in listed:
                if trimmed := str(value or "").strip():
                    return trimmed
        elif trimmed := str(listed or "").strip():
            return trimmed
        return str(fallback or "").strip()

    def integer(self, value):
        if isinstance(value, bool) or value is None:
            return 0
        if isinstance(value, int | float):
            return int(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return int(float(value.strip() or 0))
        return 0
