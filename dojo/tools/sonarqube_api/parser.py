from .importer import SonarQubeApiImporter


SCAN_SONARQUBE_API = 'SonarQube API Import'


class SonarQubeAPIParser(object):

    def get_scan_types(self):
        return [SCAN_SONARQUBE_API]

    def get_label_for_scan_types(self, scan_type):
        return SCAN_SONARQUBE_API

    def get_description_for_scan_types(self, scan_type):
        return "Aggregates findings per cwe, title, description, file_path. SonarQube output file can be imported in HTML format. Generate with https://github.com/soprasteria/sonar-report version >= 1.1.0"

    def requires_file(self, scan_type):
        return False

    def requires_tool_type(self):
        return 'SonarQube'

    def requires_API(self):
        return 'dojo.tools.sonarqube_api.api_client.SonarQubeAPI'

    def get_findings(self, json_output, test):
        return SonarQubeApiImporter().get_findings(json_output, test)
