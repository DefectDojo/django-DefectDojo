from dojo.models import Finding
from dojo.templatetags.event_tags import is_file
from dojo.tools.aqua.parser import severity_of
from dojo.tools.parser_test import ParserTest


class PTARTAssessmentParser:
    def get_test_data(self, tree):
        if "assessments" in tree:
            assessments = tree["assessments"]
        else:
            raise ValueError("Parse Error: assessments key not found in the report")

        return [finding for assessment in assessments for finding in self.parse_assessment(assessment)]

    def parse_assessment(self, assessment):
        return [Finding(
            title=hit["title"],
            description=hit["body"],
            severity=self.parse_severity(hit["severity"]),
            mitigation=hit["remediation"],
            cvssv3=hit["cvss_vector"],
            unique_id_from_tool=hit["id"],
            effort_for_fixing=self.parse_fix_effort(hit["fix_complexity"]),
            component_name=assessment["title"],
        ) for hit in assessment.get("hits", [])]

    def parse_severity(self, severity):
        severity_mapping = {
            1: "Critical",
            2: "High",
            3: "Medium",
            4: "Low"
        }
        return severity_mapping.get(severity, "Info")  # Default severity

    def parse_fix_effort(self, effort):
        effort_mapping = {
            1: "High",
            2: "Medium",
            3: "Low"
        }
        return effort_mapping.get(effort, "")
