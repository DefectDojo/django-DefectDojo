import json
from contextlib import suppress
from datetime import date as _date

from dojo.models import Finding

SEVERITY_BY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
# Calico also reports "negligible" and "unknown"; both are Info.
DEFAULT_SEVERITY = "Info"

# Calico reports this while a registry scan is still being processed.
SCAN_RESULT_UNKNOWN = "unknown"


class CalicocloudParser:

    """
    Parses a Calico Cloud Image Assurance export.

    Mirrors pkg/tools/calicocloud/connector/finding_converter field for field so a file import and an
    API sync deduplicate against each other instead of producing two copies of everything.

    Calico serves the image list and each image's vulnerabilities from two endpoints, so an export
    carries both - the vulnerabilities either nested in their image or in a map keyed by image id;
    see vulnerabilities_for(). An image whose scan result is still "Unknown" contributes nothing, the
    same as in the connector: its results are not finished, so importing them would record a partial
    scan as a complete one.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["Calico Cloud Image Assurance Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Calico Cloud Image Assurance Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Calico Cloud Image Assurance export (JSON) - the scanned images with their "
            "vulnerabilities. Matches the scan type used by the Calico Cloud connector so file and "
            "API findings deduplicate."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Calico Cloud Parser.

        Mirrors the connector's Convert:
        - title: "<id>: <name>", or whichever of the two is present.
        - severity: the CVSS v3 base score, falling back to Calico's severity word; see severity().
        - description: the advisory text, the image and digest, the package, and the fix.
        - mitigation: upgrade the package to the fixed version, when Calico names one.
        - cvssv3_score / component_name / component_version / references: straight across.
        - unsaved_vulnerability_ids: the id, but only when it is a CVE.
        - unique_id_from_tool: "calico-cloud-<image id>-<vulnerability id>".
        """
        return [
            "title",
            "severity",
            "description",
            "mitigation",
            "cvssv3_score",
            "component_name",
            "component_version",
            "references",
            "date",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "unsaved_vulnerability_ids",
            "active",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Calico Cloud Parser.

        Copied from the Calico Cloud block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields.
        """
        return ["title", "severity", "component_name", "component_version"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        findings = []
        for image in self.images(data):
            if not self.results_ready(image):
                # Calico says "Unknown" while a registry scan is still being processed. The connector
                # skips the image entirely rather than import a scan that has not finished.
                continue
            findings.extend(
                self.build_finding(vuln, image, test)
                for vuln in self.vulnerabilities_for(image, data)
            )
        return findings

    def images(self, data):
        """
        Return the scanned images in the export.

        A bare array of images is accepted, as is an object naming the list. A file that is only a
        vulnerability list is accepted too, as a single image with no image context at all - the
        identity then carries an empty image id, exactly as the connector's would.
        """
        if isinstance(data, list):
            rows = [row for row in data if isinstance(row, dict)]
            if rows and self.looks_like_vulnerability(rows[0]):
                return [{"vulnerabilities": rows}]
            return rows

        if isinstance(data, dict):
            for key in ("images", "data", "results"):
                if isinstance(data.get(key), list):
                    return [row for row in data[key] if isinstance(row, dict)]
            if isinstance(data.get("vulnerabilities"), list):
                return [data]

        msg = (
            "A Calico Cloud export is the scanned images with their vulnerabilities - a JSON array of "
            f"images, or an object with an 'images' list; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def looks_like_vulnerability(self, row):
        """A vulnerability names a package or a severity; an image names a repository or an image id."""
        vulnerability_keys = ("package", "package_name", "fixVersions", "cvss3Score")
        image_keys = ("imageID", "repository", "registry", "digest")
        return any(key in row for key in vulnerability_keys) and not any(key in row for key in image_keys)

    def vulnerabilities_for(self, image, data):
        """
        The image's vulnerabilities, nested in the image or in a map keyed by image id.

        Calico serves them from a per-image endpoint, so both shapes are what a saved export of the
        two calls looks like.
        """
        rows = image.get("vulnerabilities")
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]

        if isinstance(data, dict):
            keyed = data.get("vulnerabilities")
            if isinstance(keyed, dict):
                rows = keyed.get(str(image.get("imageID") or ""))
                if isinstance(rows, list):
                    return [row for row in rows if isinstance(row, dict)]
        return []

    def results_ready(self, image):
        """
        Whether Calico has finished processing the image's scan.

        "Unknown" in either status field means it has not. Matched case-insensitively, as the
        connector does.
        """
        for key in ("scan_result", "result"):
            if str(image.get(key) or "").strip().lower() == SCAN_RESULT_UNKNOWN:
                return False
        return True

    def build_finding(self, vuln, image, test):
        identifier = str(vuln.get("id") or "")
        package = self.package(vuln)
        fix = self.fix(vuln)

        finding = Finding(
            test=test,
            title=self.title(vuln, identifier),
            severity=self.severity(vuln),
            description=self.describe(vuln, image, package, fix),
            mitigation=f"Upgrade {package} to {fix}." if fix else None,
            component_name=package or None,
            component_version=str(vuln.get("version") or "") or None,
            references=str(vuln.get("url") or "") or None,
            unique_id_from_tool=f"calico-cloud-{image.get('imageID') or ''}-{identifier}",
            vuln_id_from_tool=identifier or None,
            # Calico scans image contents; nothing is exercised.
            static_finding=True,
            dynamic_finding=False,
            active=True,
        )
        finding.cvssv3_score = self.score(vuln)

        if identifier.strip().upper().startswith("CVE-"):
            # Only a CVE goes in as a vulnerability id; Calico also issues its own advisory ids.
            finding.unsaved_vulnerability_ids = [identifier]
        if date := self.date(image):
            finding.date = date
        return finding

    def title(self, vuln, identifier):
        name = str(vuln.get("name") or "").strip()
        if identifier and name and name != identifier:
            return f"{identifier}: {name}"
        if identifier:
            return identifier
        if name:
            return name
        return "Calico Cloud image vulnerability"

    def severity(self, vuln):
        """
        The CVSS v3 base score decides; Calico's severity word is the fallback.

        Calico's own Pass/Warn/Fail verdict is deliberately ignored - those thresholds are per-tenant
        configuration, not a severity, so importing them would make the same CVE a different severity
        in two tenants.
        """
        score = self.score(vuln)
        if score > 0:
            if score >= 9.0:
                return "Critical"
            if score >= 7.0:
                return "High"
            if score >= 4.0:
                return "Medium"
            return "Low"
        label = str(vuln.get("severity") or "").strip().lower()
        return SEVERITY_BY_LABEL.get(label, DEFAULT_SEVERITY)

    def score(self, vuln):
        """The dedicated cvss3Score field, then the nested cvss.base_score. Either may be quoted."""
        for value in (vuln.get("cvss3Score"), self.nested_score(vuln)):
            if (score := self.flex_float(value)) > 0:
                return score
        return 0.0

    def nested_score(self, vuln):
        cvss = vuln.get("cvss")
        return cvss.get("base_score") if isinstance(cvss, dict) else None

    def package(self, vuln):
        """Calico sends the package name under either key; the explicit one wins."""
        if value := str(vuln.get("package_name") or "").strip():
            return value
        return str(vuln.get("package") or "")

    def fix(self, vuln):
        """The fixed versions, joined, or the single fix string."""
        rows = vuln.get("fixVersions")
        if isinstance(rows, list) and rows:
            return ", ".join(str(row) for row in rows)
        return str(vuln.get("fix") or "")

    def describe(self, vuln, image, package, fix):
        lines = []

        def write(label, value):
            if str(value or "").strip():
                lines.append(f"**{label}:** {value}")

        write("Description", str(vuln.get("description") or ""))
        write("Image", self.image_reference(image))
        write("Digest", str(image.get("digest") or ""))
        write("Package", package)
        write("Installed version", str(vuln.get("version") or ""))
        write("Fixed in", fix)
        return "\n".join(lines).strip()

    def image_reference(self, image):
        """
        "<registry>/<repository>:<tag>", falling back to the digest and then the image id.

        The registry is only prefixed when there is a repository to prefix, matching the connector.
        """
        name = str(image.get("repository") or "").strip()
        registry = str(image.get("registry") or "").strip()
        if registry and name:
            name = f"{registry.strip('/')}/{name}"

        tag = str(image.get("tag") or "")
        if name and tag:
            return f"{name}:{tag}"
        if name:
            return name
        if digest := str(image.get("digest") or ""):
            return digest
        return str(image.get("imageID") or "")

    def date(self, image):
        """
        The image's scan timestamp - the result time, then when it was scanned.

        The connector takes the first ten characters because it hands the API a string; this reads
        the same ten as an ISO date, and skips one that is not a date rather than failing the import.
        """
        for key in ("resultTime", "scanned"):
            value = str(image.get(key) or "").strip()
            if len(value) >= 10:
                with suppress(ValueError):
                    return _date.fromisoformat(value[:10])
        return None

    def flex_float(self, value):
        """Calico's numbers may arrive as JSON numbers or quoted strings."""
        if isinstance(value, bool) or value is None:
            return 0.0
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            with suppress(ValueError):
                return float(value.strip() or 0)
        return 0.0
