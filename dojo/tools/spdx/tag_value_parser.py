import logging

from dojo.tools.spdx.json_parser import SpdxJSONParser

LOGGER = logging.getLogger(__name__)

# Tag-value keys that begin a new package block, and the keys this parser reads inside one.
PACKAGE_START = "PackageName"


class SpdxTagValueParser:

    """
    Parse an SPDX 2.2 / 2.3 document in tag-value format.

    Tag-value is line-oriented `Tag: Value` text. Rather than duplicating the mapping logic, this
    parser converts the document into the same dict shape the JSON serialisation uses and hands it to
    SpdxJSONParser.findings_from_document, so both serialisations are guaranteed to produce identical
    findings.

    ExternalRef lines have the form:
        ExternalRef: <category> <type> <locator>
    optionally followed by:
        ExternalRefComment: <text>
    """

    def get_findings(self, file, test):
        content = file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        document = self._to_document(content)
        return SpdxJSONParser().findings_from_document(document, test)

    def _to_document(self, content):
        """Convert tag-value text into the SPDX JSON document shape."""
        document = {"spdxVersion": "", "creationInfo": {}, "packages": []}
        current = None
        last_ref = None

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue

            tag, _, value = line.partition(":")
            tag = tag.strip()
            value = value.strip()

            if tag == PACKAGE_START:
                current = {"name": value, "externalRefs": [], "checksums": []}
                document["packages"].append(current)
                last_ref = None
                continue

            if current is None:
                # Document-level tags, which appear before the first package block.
                self._apply_document_tag(document, tag, value)
                continue

            last_ref = self._apply_package_tag(current, tag, value, last_ref)

        return document

    def _apply_document_tag(self, document, tag, value):
        if tag == "SPDXVersion":
            document["spdxVersion"] = value
        elif tag == "Created":
            document["creationInfo"]["created"] = value
        elif tag == "DocumentName":
            document["name"] = value
        elif tag == "SPDXID":
            document["SPDXID"] = value

    def _apply_package_tag(self, package, tag, value, last_ref):
        """Apply one tag to the current package. Returns the external ref a comment would attach to."""
        simple = {
            "SPDXID": "SPDXID",
            "PackageVersion": "versionInfo",
            "PackageLicenseConcluded": "licenseConcluded",
            "PackageLicenseDeclared": "licenseDeclared",
            "PackageSupplier": "supplier",
            "PackageOriginator": "originator",
            "PackageDownloadLocation": "downloadLocation",
            "PackageDescription": "description",
        }
        if tag in simple:
            package[simple[tag]] = value
            return None

        if tag == "PackageChecksum":
            # "PackageChecksum: SHA256: <hex>"
            algorithm, _, checksum = value.partition(":")
            if checksum:
                package["checksums"].append({
                    "algorithm": algorithm.strip(),
                    "checksumValue": checksum.strip(),
                })
            return None

        if tag == "ExternalRef":
            # "ExternalRef: SECURITY advisory https://example.com/advisory/CVE-2024-0001"
            parts = value.split(None, 2)
            if len(parts) == 3:
                ref = {
                    "referenceCategory": parts[0],
                    "referenceType": parts[1],
                    "referenceLocator": parts[2],
                }
                package["externalRefs"].append(ref)
                return ref
            LOGGER.debug("skipping malformed SPDX ExternalRef line: %r", value)
            return None

        if tag == "ExternalRefComment" and last_ref is not None:
            last_ref["comment"] = value
            # A comment may only follow its own ExternalRef, so the pairing ends here.
            return None

        return last_ref
