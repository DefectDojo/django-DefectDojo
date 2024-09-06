from dojo.tools.parser_test import ParserTest


class PTARTAssessmentParser:
    def get_test_data(self, tree):
        if "assessments" in tree:
            assessments = tree["assessments"]
        else:
            raise ValueError("Parse Error: assessments key not found in the report")

        return [self.parse_assessment(assessment) for assessment in assessments]

    def parse_assessment(self, assessment):
        test = ParserTest(name=assessment["title"], type="Pen Test", version=None)
        return test

    def get_findings_for(self, assessment_name, data):
        return []