import dojo.tools.ptart.ptart_parser_tools as ptart_tools
from dojo.models import Finding


def generate_retest_hit_title(hit, original_hit):
    # Fake a title for the retest hit with the fix status if available
    title = original_hit.get("title", "")
    hit_id = hit.get("id", None)
    if "status" in hit:
        title = f"{title} ({ptart_tools.parse_retest_status(hit['status'])})"
    fake_retest_hit = {
        "title": title,
        "id": hit_id,
    }
    return ptart_tools.parse_title_from_hit(fake_retest_hit)


class PTARTRetestParser:
    def __init__(self):
        self.cvss_type = None

    def get_test_data(self, tree):
        if "retests" in tree:
            self.cvss_type = tree.get("cvss_type", None)
            retests = tree["retests"]
        else:
            return []

        return [finding for retest in retests
                for finding in self.parse_retest(retest)]

    def parse_retest(self, retest):
        hits = retest.get("hits", [])
        # Get all the potential findings, valid or not.
        all_findings = [self.get_finding(retest, hit) for hit in hits]
        # We want to make sure we include only valid findings for a retest.
        return [finding for finding in all_findings if finding is not None]

    def get_finding(self, retest, hit):

        # The negatives are a bit confusing, but we want to skip hits that
        # don't have an original hit. Hit is invalid in a retest if not linked
        # to an original.
        if "original_hit" not in hit or not hit["original_hit"]:
            return None

        # Get the original hit from the retest
        original_hit = hit["original_hit"]

        # Set the Finding title to the original hit title with the retest
        # status if available. We don't really have any other places to set
        # this field.
        finding_title = generate_retest_hit_title(hit, original_hit)

        # As the retest hit doesn't have a date added, use the start of the
        # retest campaign as something that's close enough.
        finding = Finding(
            title=finding_title,
            severity=ptart_tools.parse_ptart_severity(
                original_hit.get("severity"),
            ),
            effort_for_fixing=ptart_tools.parse_ptart_fix_effort(
                original_hit.get("fix_complexity"),
            ),
            component_name=f"Retest: {retest.get('name', 'Retest')}",
            date=ptart_tools.parse_date(
                retest.get("start_date"),
                "%Y-%m-%d",
            ),
        )

        # Don't add the fields if they are blank.
        if hit["body"]:
            finding.description = hit.get("body")

        if original_hit["remediation"]:
            finding.mitigation = original_hit.get("remediation")

        if hit["id"]:
            finding.unique_id_from_tool = hit.get("id")
            finding.vuln_id_from_tool = original_hit.get("id")
            finding.cve = original_hit.get("id")

        cvss_vector = ptart_tools.parse_cvss_vector(
            original_hit,
            self.cvss_type,
        )
        if cvss_vector:
            finding.cvssv3 = cvss_vector

        if "labels" in original_hit:
            finding.unsaved_tags = original_hit["labels"]

        finding.unsaved_endpoints = ptart_tools.parse_endpoints_from_hit(
            original_hit,
        )

        # We only have screenshots in a retest. Refer to the original hit for
        # the attachments.
        finding.unsaved_files = ptart_tools.parse_screenshots_from_hit(hit)

        return finding
