from .importer import LaceworkApiImporter

SCAN_LACEWORK_API = "Lacework API Import"


class ApiLaceworkParser:
    def get_scan_types(self):
        """Return the scan types supported by this parser."""
        return [SCAN_LACEWORK_API]

    def get_label_for_scan_types(self, scan_type):
        """Return the label for the given scan type."""
        return SCAN_LACEWORK_API

    def get_description_for_scan_types(self, scan_type):
        """Return the description for the given scan type."""
        return (
            "Lacework vulnerabilities can be directly imported using the Lacework API. "
            "An API Scan Configuration has to be setup in the Product. "
            "This importer fetches container and host vulnerabilities from Lacework API v2.0 "
            "and maps them to DefectDojo Findings."
        )

    def requires_file(self, scan_type):
        """Indicate that no file upload is required (API-based import)."""
        return False

    def requires_tool_type(self, scan_type):
        """Return the required Tool Type name."""
        return "Lacework"

    def api_scan_configuration_hint(self):
        """Return a hint for configuring the API scan."""
        from dojo.models import Tool_Type  # noqa: PLC0415

        tool_type_id = Tool_Type.objects.filter(name="Lacework").values_list("id", flat=True).first() or ""
        return (
            f"Tool type <b>Lacework</b> exists however parser <b>Lacework API Import</b> "
            f'requires at least one <a href="/tool_config/add?tool_type={tool_type_id}">tool configuration</a>.'
        )

    def get_findings(self, json_output, test):
        """Import findings from Lacework API."""
        return LaceworkApiImporter().get_findings(json_output, test)
