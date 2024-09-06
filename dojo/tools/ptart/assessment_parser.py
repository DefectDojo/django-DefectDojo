from dojo.models import Finding
from dojo.tools.parser_test import ParserTest


class PTARTAssessmentParser:
    def get_test_data(self, tree):
        if "assessments" in tree:
            assessments = tree["assessments"]
        else:
            raise ValueError("Parse Error: assessments key not found in the report")

        return [finding for assessment in assessments for finding in self.parse_assessment(assessment)]

    def parse_assessment(self, assessment):
        return [Finding(title=hit["title"]) for hit in assessment.get("hits", [])]

