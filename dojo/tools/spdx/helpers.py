import re

# SPDX uses the literal "NOASSERTION" (and sometimes "NONE") where a value is unknown. Those are
# placeholders, not data, so they are treated as absent everywhere in this parser.
SPDX_PLACEHOLDERS = {"NOASSERTION", "NONE", ""}

# SPDX external-reference categories and types the parser cares about.
CATEGORY_SECURITY = "SECURITY"
CATEGORY_PACKAGE_MANAGER = "PACKAGE-MANAGER"

# Reference types under the SECURITY category that identify a component rather than describe a
# weakness. A CPE says "this is what the package IS"; it is not a vulnerability, so it must never
# produce a finding.
IDENTITY_SECURITY_TYPES = {"cpe22Type", "cpe23Type"}

# Reference types under the SECURITY category that point at a weakness.
ADVISORY_SECURITY_TYPES = {"advisory", "fix", "url", "swid"}

# CVE-2024-12345 style identifiers, and the GitHub/GitLab advisory identifiers commonly used in
# SPDX advisory URLs.
VULN_ID_PATTERN = re.compile(
    r"(CVE-\d{4}-\d{4,})|(GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})",
    re.IGNORECASE,
)


def clean(value):
    """Return a stripped value, or "" for SPDX placeholders such as NOASSERTION."""
    if value is None:
        return ""
    value = str(value).strip()
    if value.upper() in SPDX_PLACEHOLDERS:
        return ""
    return value


def collect_checksums(checksums):
    """
    Convert an SPDX package's checksums list into the {algorithm: [values]} shape LocationData wants.

    Mirrors Cyclonedxhelper._collect_hashes so the two SBOM formats produce identical location data.
    """
    if not checksums:
        return {}
    hashes = {}
    for checksum in checksums:
        if not isinstance(checksum, dict):
            continue
        algorithm = clean(checksum.get("algorithm")).lower()
        value = clean(checksum.get("checksumValue"))
        if algorithm and value:
            hashes.setdefault(algorithm, []).append(value)
    return hashes


def license_expression(package):
    """
    Build a license expression for an SPDX package.

    SPDX carries two license fields with different meanings: licenseConcluded is the SBOM author's
    determination, licenseDeclared is what the package itself claims. The concluded value wins when
    present, matching how SPDX consumers are expected to read it; otherwise the declared value is used.
    """
    concluded = clean(package.get("licenseConcluded"))
    if concluded:
        return concluded
    return clean(package.get("licenseDeclared"))


def external_refs(package):
    """Yield the package's external references as dicts, tolerating a missing or malformed list."""
    refs = package.get("externalRefs")
    if not isinstance(refs, list):
        return
    for ref in refs:
        if isinstance(ref, dict):
            yield ref


def package_purl(package):
    """Return the package's Package URL from its PACKAGE-MANAGER external reference, or ""."""
    for ref in external_refs(package):
        if clean(ref.get("referenceType")) == "purl":
            return clean(ref.get("referenceLocator"))
    return ""


def package_cpes(package):
    """Return the package's CPE identifiers. These describe identity and never become findings."""
    cpes = []
    for ref in external_refs(package):
        if clean(ref.get("referenceCategory")).upper() != CATEGORY_SECURITY:
            continue
        if clean(ref.get("referenceType")) in IDENTITY_SECURITY_TYPES:
            locator = clean(ref.get("referenceLocator"))
            if locator:
                cpes.append(locator)
    return cpes


def package_advisories(package):
    """
    Return the package's SECURITY external references that point at a weakness.

    Only advisory-style reference types are considered. A cpe22Type/cpe23Type reference also lives
    under the SECURITY category but is an identifier for the package itself, so including it here
    would turn every inventoried package into a bogus vulnerability.
    """
    advisories = []
    for ref in external_refs(package):
        if clean(ref.get("referenceCategory")).upper() != CATEGORY_SECURITY:
            continue
        reference_type = clean(ref.get("referenceType"))
        if reference_type not in ADVISORY_SECURITY_TYPES:
            continue
        locator = clean(ref.get("referenceLocator"))
        if not locator:
            continue
        advisories.append({
            "type": reference_type,
            "locator": locator,
            "comment": clean(ref.get("comment")),
        })
    return advisories


def vulnerability_ids_in(text):
    """
    Extract vulnerability identifiers from a string, preserving order and dropping duplicates.

    SPDX 2.x has no vulnerability container, so an advisory reference's URL or comment is the only
    place a CVE can appear.
    """
    found = []
    for match in VULN_ID_PATTERN.finditer(text or ""):
        identifier = match.group(0).upper()
        if identifier not in found:
            found.append(identifier)
    return found
