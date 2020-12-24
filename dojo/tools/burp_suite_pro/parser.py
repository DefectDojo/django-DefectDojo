import logging
import json
from dojo.models import Finding

logger = logging.getLogger(__name__)


DESCRIPTION_TEMPLATE = """**{title}**
**Serial Number**: {serial_number}
**Type Index**: {type_index}
**Confidence**: {confidence}
{description_text}
"""


class BurpSuiteProParser(object):
    """"""

    def __init__(self, file, test):
        self.items = []

        # API export is a JSON file
        tree = json.load(file)

        # by default give the test a title
        test.title = f"Burp Suite Pro scan ({file.name})"

        # for each issue found
        for issue_event in tree.get("issue_events", list()):
            if "issue_found" == issue_event.get("type"):
                verified = False
                false_p = False
                duplicate = False
                out_of_scope = False
                impact = None
                mitigated = None
                title = issue_event["issue"]["name"]
                severity = issue_event["issue"]["severity"].title()
                description_formated = DESCRIPTION_TEMPLATE.format(
                    title=title,
                    serial_number=issue_event["issue"]["serial_number"],
                    type_index=issue_event["issue"]["type_index"],
                    confidence=issue_event["issue"]["confidence"],
                    description_text=issue_event["issue"]["description"],
                )

                finding = Finding(
                    title=title,
                    test=test,
                    severity=severity,
                    numerical_severity=Finding.get_numerical_severity(severity),
                    description=description_formated,
                    mitigation="No mitigation provided",
                    references="No references provided",
                    cve=None,  # for now CVE are not managed or it's not very clear how in the spec
                    cwe=0,
                    active=True,
                    verified=verified,
                    false_p=false_p,
                    duplicate=duplicate,
                    out_of_scope=out_of_scope,
                    mitigated=mitigated,
                    impact="No impact provided",
                    static_finding=False,  # by definition
                    dynamic_finding=True,  # by definition
                    unique_id_from_tool=str(
                        issue_event["issue"]["serial_number"]
                    ),  # the serial number is a good candidate for this attribute
                    vuln_id_from_tool=str(
                        issue_event["issue"]["type_index"]
                    ),  # the type index is a good candidate for this attribute
                )
                self.items.append(finding)
