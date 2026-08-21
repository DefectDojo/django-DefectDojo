import logging

from cvss import CVSS3

LOGGER = logging.getLogger(__name__)


class Cyclonedxhelper:
    def _get_cvssv3(self, raw_vector):
        if raw_vector is None or not raw_vector:
            return None
        if not raw_vector.startswith("CVSS:3"):
            raw_vector = "CVSS:3.1/" + raw_vector
        try:
            return CVSS3(raw_vector)
        except BaseException:
            LOGGER.exception(
                "error while parsing vector CVSS v3 %s", raw_vector,
            )
            return None

    def _get_component(self, components, reference):
        if reference not in components:
            LOGGER.warning("reference:%s not found in the BOM", reference)
            return (None, None)
        if "version" not in components[reference]:
            return (components[reference]["name"], None)
        return (
            components[reference]["name"],
            components[reference]["version"],
        )

    def _collect_hashes(self, raw_hashes):
        """Convert CycloneDX hash list to dict mapping algorithm to lists of hash values."""
        if not raw_hashes:
            return {}
        hashes = {}
        for h in raw_hashes:
            alg = h.get("alg", "").lower()
            content = h.get("content", "")
            if alg and content:
                hashes.setdefault(alg, []).append(content)
        return hashes

    @staticmethod
    def extract_license_expression_json(component: dict) -> str:
        """
        Extract a license expression string from a CycloneDX JSON component.

        Prefers SPDX expression, then joins license IDs/names with ' OR '.
        """
        licenses = component.get("licenses", [])
        if not licenses:
            return ""
        # Check for a top-level SPDX expression first
        for entry in licenses:
            if expression := entry.get("expression"):
                return expression
        # Fall back to joining individual license id or name values
        parts = []
        for entry in licenses:
            lic = entry.get("license", {})
            if lic_id := lic.get("id"):
                parts.append(lic_id)
            elif lic_name := lic.get("name"):
                parts.append(lic_name)
        return " OR ".join(parts)

    @staticmethod
    def extract_license_expression_xml(component_elem, namespace: str) -> str:
        """
        Extract a license expression string from a CycloneDX XML component element.

        Prefers SPDX expression, then joins license id/name values with ' OR '.
        """
        # Check for <expression> element (CycloneDX 1.5+)
        expression_elem = component_elem.find(f"{namespace}licenses/{namespace}expression")
        if expression_elem is not None and expression_elem.text:
            return expression_elem.text
        # Fall back to individual <license> entries
        parts = []
        for lic_elem in component_elem.findall(f"{namespace}licenses/{namespace}license"):
            lic_id = lic_elem.findtext(f"{namespace}id")
            if lic_id:
                parts.append(lic_id)
            else:
                lic_name = lic_elem.findtext(f"{namespace}name")
                if lic_name:
                    parts.append(lic_name)
        return " OR ".join(parts)

    def fix_severity(self, severity):
        severity = severity.capitalize()
        if severity is None:
            severity = "Medium"
        elif severity in {"Unknown", "None"}:
            severity = "Info"
        return severity
