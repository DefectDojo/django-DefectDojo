import logging

from cvss import CVSS3

LOGGER = logging.getLogger(__name__)


class Cyclonedxhelper:
    def _get_cvssv3(self, raw_vector):
        if raw_vector is None or raw_vector == "":
            return None
        if not raw_vector.startswith("CVSS:3"):
            raw_vector = "CVSS:3.1/" + raw_vector
        try:
            return CVSS3(raw_vector)
        except BaseException:
            LOGGER.exception(
                f"error while parsing vector CVSS v3 {raw_vector}",
            )
            return None

    def _get_component(self, components, reference):
        if reference not in components:
            LOGGER.warning(f"reference:{reference} not found in the BOM")
            return (None, None)
        if "version" not in components[reference]:
            return (components[reference]["name"], None)
        return (
            components[reference]["name"],
            components[reference]["version"],
        )

    def fix_severity(self, severity):
        severity = severity.capitalize()
        if severity is None:
            severity = "Medium"
        elif severity == "Unknown" or severity == "None":
            severity = "Info"
        return severity
