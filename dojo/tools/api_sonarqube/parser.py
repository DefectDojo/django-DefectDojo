from .importer import SonarQubeApiImporter

SCAN_SONARQUBE_API = "SonarQube API Import"


class ApiSonarQubeParser:
    def get_scan_types(self):
        return [SCAN_SONARQUBE_API]

    def get_label_for_scan_types(self, scan_type):
        return SCAN_SONARQUBE_API

    def get_description_for_scan_types(self, scan_type):
        return (
            "SonarQube findings can be directly imported using the SonarQube API. An API Scan Configuration has "
            "to be setup in the Product."
        )

    def requires_file(self, scan_type):
        return False

    def requires_tool_type(self, scan_type):
        return "SonarQube"

    def api_scan_configuration_hint(self):
        return (
            "the field <b>Service key 1</b> has to be set with the SonarQube project key. <b>Service key 2</b> "
            "can be used for the Organization ID if using SonarCloud."
        )

    def get_findings(self, json_output, test, branch_tag):
        return SonarQubeApiImporter().get_findings(json_output, test, branch_tag)
