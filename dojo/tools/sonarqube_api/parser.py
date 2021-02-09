from .importer import SonarQubeApiImporter


class SonarQubeAPIParser(object):

    def get_scan_types(self):
        return ["SonarQube API Import"]

    def get_label_for_scan_types(self, scan_type):
        return "SonarQube API Import"

    def get_description_for_scan_types(self, scan_type):
        return "Aggregates findings per cwe, title, description, file_path. SonarQube output file can be imported in HTML format. Generate with https://github.com/soprasteria/sonar-report version >= 1.1.0"

    def get_findings(self, json_output, test):
        return SonarQubeApiImporter().get_findings(json_output, test)
