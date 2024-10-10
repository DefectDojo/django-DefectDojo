import dojo.tools.ptart.ptart_parser_tools as ptart_tools
from dojo.models import Finding


class PTARTAssessmentParser:
    def __init__(self):
        self.cvss_type = None

    def get_test_data(self, tree):
        # Check that the report is valid, If we have no assessments, then return an empty list
        if "assessments" not in tree:
            return []

        self.cvss_type = tree.get("cvss_type", None)
        assessments = tree["assessments"]
        return [finding for assessment in assessments for finding in self.parse_assessment(assessment)]

    def parse_assessment(self, assessment):
        hits = assessment.get("hits", [])
        return [self.get_finding(assessment, hit) for hit in hits]

    def get_finding(self, assessment, hit):
        finding = Finding(
            title=ptart_tools.parse_title_from_hit(hit),
            severity=ptart_tools.parse_ptart_severity(hit.get("severity", 5)),
            effort_for_fixing=ptart_tools.parse_ptart_fix_effort(hit.get("fix_complexity", 3)),
            component_name=assessment.get("title", "Unknown Component"),
            date=ptart_tools.parse_date_added_from_hit(hit),
        )

        # Don't add fields if they are blank
        if "body" in hit and hit["body"]:
            finding.description = hit["body"]

        if "remediation" in hit and hit["remediation"]:
            finding.mitigation = hit["remediation"]

        if "id" in hit and hit["id"]:
            finding.unique_id_from_tool = hit.get("id")

        # Clean up and parse the CVSS vector
        cvss_vector = ptart_tools.parse_cvss_vector(hit, self.cvss_type)
        if cvss_vector:
            finding.cvssv3 = cvss_vector

        if "labels" in hit:
            finding.unsaved_tags = hit["labels"]

        finding.unsaved_endpoints = ptart_tools.parse_endpoints_from_hit(hit)

        # Add screenshots to files, and add other attachments to the files as well.
        finding.unsaved_files = ptart_tools.parse_screenshots_from_hit(hit)
        finding.unsaved_files.extend(ptart_tools.parse_attachment_from_hit(hit))

        return finding
