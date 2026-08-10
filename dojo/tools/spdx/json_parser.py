import json
import logging

import dateutil.parser
from django.conf import settings

from dojo.models import Finding
from dojo.tools.locations import LocationData
from dojo.tools.spdx.helpers import (
    clean,
    collect_checksums,
    license_expression,
    package_advisories,
    package_cpes,
    package_purl,
    vulnerability_ids_in,
)

LOGGER = logging.getLogger(__name__)


class SpdxJSONParser:

    """
    Parse an SPDX 2.2 / 2.3 document in JSON format.

    SPDX 3.0 uses a completely different JSON-LD serialisation (an @graph of typed elements rather
    than a packages array). It is rejected with a clear message rather than silently mis-parsed.
    """

    def get_findings(self, file, test):
        return self.findings_from_document(json.load(file), test)

    def findings_from_document(self, data, test):
        """Map an already-decoded SPDX document. The tag-value parser reuses this directly."""
        if not isinstance(data, dict):
            msg = "This SPDX JSON file is not an object; expected an SPDX document."
            raise TypeError(msg)

        self._reject_unsupported_version(data)

        report_date = self._report_date(data)
        packages = [p for p in data.get("packages", []) if isinstance(p, dict)]

        # Component inventory. SPDX and CycloneDX must behave identically here: the component list is
        # recorded as location metadata on the test, NOT converted into findings. An inventoried
        # package is not a weakness, and manufacturing a finding per package would flood the product
        # with rows nobody can remediate.
        if settings.V3_FEATURE_LOCATIONS:
            for package in packages:
                location = self._location_for(package)
                if location:
                    test.unsaved_metadata.append(location)

        # Findings. SPDX 2.x has no vulnerability container, so the only weakness signal in the format
        # is a SECURITY external reference of an advisory type carrying a vulnerability identifier.
        findings = {}
        for package in packages:
            for finding in self._findings_for_package(package, test, report_date):
                # One finding per (package, vulnerability id): the same CVE can be referenced by both
                # an advisory URL and a fix URL on the same package.
                findings.setdefault(finding.unique_id_from_tool, finding)

        return list(findings.values())

    def _reject_unsupported_version(self, data):
        """Reject SPDX 3.x, whose JSON-LD shape this parser does not understand."""
        version = clean(data.get("spdxVersion"))
        if version.startswith("SPDX-3"):
            msg = (
                f"SPDX {version} uses the JSON-LD serialisation, which this parser does not support yet. "
                "Export the SBOM as SPDX 2.2 or 2.3 JSON, or as SPDX tag-value."
            )
            raise ValueError(msg)
        # An SPDX 3.0 JSON-LD document may carry no spdxVersion at all, using @context/@graph instead.
        if not version and ("@graph" in data or "@context" in data):
            msg = (
                "This looks like an SPDX 3.x JSON-LD document, which this parser does not support yet. "
                "Export the SBOM as SPDX 2.2 or 2.3 JSON, or as SPDX tag-value."
            )
            raise ValueError(msg)

    def _report_date(self, data):
        """Return the document's creation timestamp, or None when it is absent or unparseable."""
        created = clean((data.get("creationInfo") or {}).get("created"))
        if not created:
            return None
        try:
            return dateutil.parser.parse(created)
        except (ValueError, OverflowError, dateutil.parser.ParserError):
            LOGGER.debug("could not parse SPDX creationInfo.created value %r", created)
            return None

    def _location_for(self, package):
        """Build the dependency location for one SPDX package, or None when it has no identity."""
        name = clean(package.get("name"))
        version = clean(package.get("versionInfo"))
        purl = package_purl(package)
        if not purl and not name:
            return None

        checksums = collect_checksums(package.get("checksums"))
        licenses = license_expression(package)

        if purl:
            return LocationData.dependency(
                purl=purl,
                artifact_hashes=checksums,
                license_expression=licenses,
            )
        # No PURL: fall back to name/version, exactly as the CycloneDX parser does.
        return LocationData.dependency(
            name=name,
            version=version,
            artifact_hashes=checksums,
            license_expression=licenses,
        )

    def _findings_for_package(self, package, test, report_date):
        """Yield one finding per vulnerability identifier referenced by this package's advisories."""
        advisories = package_advisories(package)
        if not advisories:
            return

        name = clean(package.get("name")) or "unknown component"
        version = clean(package.get("versionInfo"))

        # Group the references by vulnerability id so a CVE named by both an advisory and a fix URL
        # yields one finding carrying both links.
        by_vuln_id = {}
        for advisory in advisories:
            haystack = f"{advisory['locator']} {advisory['comment']}"
            for vuln_id in vulnerability_ids_in(haystack):
                by_vuln_id.setdefault(vuln_id, []).append(advisory)

        for vuln_id, refs in by_vuln_id.items():
            yield self._build_finding(package, name, version, vuln_id, refs, test, report_date)

    def _build_finding(self, package, name, version, vuln_id, refs, test, report_date):
        title = f"{name}:{version} | {vuln_id}" if version else f"{name} | {vuln_id}"

        finding = Finding(
            title=title,
            test=test,
            description=self._description(package, name, version, vuln_id, refs),
            # SPDX advisory references carry no severity, score or vector - the format has no field
            # for them. Medium is used rather than Info so a real, named CVE is not filtered out of
            # sight by a minimum-severity setting. Re-rank in DefectDojo, or import the scanner's own
            # report alongside the SBOM for scored findings.
            severity="Medium",
            mitigation=(
                f"Review the referenced advisory for {vuln_id} and upgrade {name} to a release that "
                "resolves it. SPDX does not carry fixed-version information."
            ),
            references="\n".join(self._reference_lines(refs)),
            component_name=name,
            component_version=version,
            static_finding=True,
            dynamic_finding=False,
            vuln_id_from_tool=vuln_id,
            unique_id_from_tool=f"{package.get('SPDXID', name)}|{vuln_id}",
        )
        finding.unsaved_vulnerability_ids = [vuln_id]

        if report_date:
            finding.date = report_date

        if settings.V3_FEATURE_LOCATIONS:
            location = self._location_for(package)
            if location:
                finding.unsaved_locations.append(location)

        return finding

    def _description(self, package, name, version, vuln_id, refs):
        parts = [
            f"The SBOM records a security advisory for **{name}"
            + (f" {version}" if version else "")
            + f"** referencing **{vuln_id}**.",
        ]

        if purl := package_purl(package):
            parts.append(f"**PURL:** {purl}")

        # CPEs are recorded for identification. They are deliberately NOT treated as vulnerabilities.
        if cpes := package_cpes(package):
            parts.append("**CPE:** " + ", ".join(cpes))

        if licenses := license_expression(package):
            parts.append(f"**License:** {licenses}")

        if supplier := clean(package.get("supplier")):
            parts.append(f"**Supplier:** {supplier}")

        parts.append(
            "SPDX carries no severity, CVSS score or fix version for an advisory reference, so this "
            "finding records the association only. Import the scanner's own report for scored findings.",
        )
        return "\n\n".join(parts)

    def _reference_lines(self, refs):
        lines = []
        for advisory in refs:
            line = f"**{advisory['type']}:** {advisory['locator']}"
            if advisory["comment"]:
                line += f" ({advisory['comment']})"
            if line not in lines:
                lines.append(line)
        return lines
