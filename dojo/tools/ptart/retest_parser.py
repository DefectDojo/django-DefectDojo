import dojo.tools.ptart.ptart_parser_tools as ptart_tools
from dojo.models import Finding
from dojo.tools.ptart.ptart_parser_tools import parse_title_from_hit


def generate_retest_hit_title(hit, original_hit):
    # Fake a title for the retest hit with the fix status if available
    title = original_hit.get("title", "")
    hit_id = hit.get("id", None)
    if "status" in hit:
        title = f"{title} ({ptart_tools.parse_retest_fix_status(hit['status'])})"
    fake_retest_hit = {
        "title": title,
        "id": hit_id,
    }
    finding_title = parse_title_from_hit(fake_retest_hit)
    return finding_title


class PTARTRetestParser:
    def __init__(self):
        self.cvss_type = None

    def get_test_data(self, tree):
        if "retests" in tree:
            self.cvss_type = tree.get("cvss_type", None)
            retests = tree["retests"]
        else:
            raise ValueError("Parse Error: retests key not found in the report")

        return [finding for retest in retests for finding in self.parse_retest(retest)]

    def parse_retest(self, retest):
        return [self.get_finding(retest, hit) for hit in retest.get("hits", [])]

    def get_finding(self, retest, hit):

        # Get the original hit from the retest
        original_hit = None
        if "original_hit" in hit:
            original_hit = hit["original_hit"]

        # Guard
        if original_hit is None:
            raise ValueError("Parse Error: original_hit key not found in the report")

        finding_title = generate_retest_hit_title(hit, original_hit)

        finding = Finding(
            title=finding_title,
            severity=ptart_tools.parse_ptart_severity(original_hit.get("severity", 5)),
            effort_for_fixing=ptart_tools.parse_ptart_fix_effort(original_hit.get("fix_complexity", 3)),
            component_name=f"Retest: {retest.get('name', 'Retest')}",
            date=ptart_tools.parse_date(retest.get("start_date"), "%Y-%m-%d"),
        )

        if "body" in hit:
            finding.description = hit["body"]

        if "remediation" in original_hit:
            finding.mitigation = original_hit["remediation"]

        if "id" in hit:
            finding.unique_id_from_tool = hit.get("id")

        cvss_vector = ptart_tools.parse_cvss_vector(original_hit, self.cvss_type)
        if cvss_vector:
            finding.cvssv3 = cvss_vector

        finding.unsaved_tags = original_hit["labels"]

        finding.unsaved_endpoints = ptart_tools.parse_endpoints_from_hit(original_hit)

        finding.unsaved_files = ptart_tools.parse_screenshots_from_hit(hit)

        return finding
