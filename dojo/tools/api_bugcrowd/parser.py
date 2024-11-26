import json
import logging
import re
import textwrap
from datetime import datetime

import dateutil.parser
from django.core.exceptions import ValidationError

from dojo.models import Endpoint, Finding

from .importer import BugcrowdApiImporter

SCAN_BUGCROWD_API = "Bugcrowd API Import"

pattern_title_authorized = re.compile(r"^[a-zA-Z0-9_\s+-.]*$")

logger = logging.getLogger(__name__)


class ApiBugcrowdParser:

    """Import from Bugcrowd API /submissions"""

    def get_scan_types(self):
        return [SCAN_BUGCROWD_API]

    def get_label_for_scan_types(self, scan_type):
        return SCAN_BUGCROWD_API

    def get_description_for_scan_types(self, scan_type):
        return (
            "Bugcrowd submissions can be directly imported using the Bugcrowd API. An API Scan Configuration has "
            "to be setup in the Product."
        )

    def requires_file(self, scan_type):
        return False

    def requires_tool_type(self, scan_type):
        return "Bugcrowd API"

    def api_scan_configuration_hint(self):
        return (
            "the field <b>Service key 1</b> has to be set with the Bugcrowd program code. <b>Service key 2</b> "
            "can be set with the target in the Bugcrowd program (will be url encoded for the api call), "
            "if not supplied, will fetch all submissions in the program"
        )

    def get_findings(self, file, test):
        api_scan_config = None
        if file is None:
            data, api_scan_config = BugcrowdApiImporter().get_findings(test)
        else:
            data = json.load(file)
        findings = []

        for entry in data:
            if not self.include_finding(entry):
                continue
            if test.api_scan_configuration:
                config = test.api_scan_configuration
                links = "https://tracker.bugcrowd.com/{}{}".format(
                    str(config.service_key_1), entry["links"]["self"],
                )
            if api_scan_config is not None:
                links = "https://tracker.bugcrowd.com/{}{}".format(
                    str(api_scan_config.service_key_1), entry["links"]["self"],
                )
            else:
                links = None
                if "links" in entry and "self" in entry["links"]:
                    links = entry["links"]["self"]

            bugcrowd_state = entry["attributes"]["state"]
            entry["attributes"]["duplicate"]
            bugcrowd_severity = entry["attributes"]["severity"]

            title = entry["attributes"]["title"]

            if not pattern_title_authorized.match(title):
                char_to_replace = {":": " ", '"': " ", "@": "at"}
                for key, value in char_to_replace.items():
                    title = title.replace(key, value)

            date = dateutil.parser.parse(entry["attributes"]["submitted_at"])

            bug_url = ""
            bug_endpoint = None
            if entry["attributes"]["bug_url"]:
                try:
                    if (
                        "://" in entry["attributes"]["bug_url"]
                    ):  # is the host full uri?
                        bug_endpoint = Endpoint.from_uri(
                            entry["attributes"]["bug_url"].strip(),
                        )
                        # can raise exception if the host is not valid URL
                    else:
                        bug_endpoint = Endpoint.from_uri(
                            "//" + entry["attributes"]["bug_url"].strip(),
                        )
                        # can raise exception if there is no way to parse the
                        # host
                except (
                    ValueError
                ):  # We don't want to fail the whole import just for 1 error in the bug_url
                    logger.error("Error parsing bugcrowd bug_url : %s", entry["attributes"]["bug_url"].strip())
                bug_url = entry["attributes"]["bug_url"]

            description = "\n".join(
                [
                    entry["attributes"]["description"],
                    "",
                    "Bugcrowd details:",
                    f"- Severity: P{bugcrowd_severity}",
                    f"- Bug Url: [{bug_url}]({bug_url})",
                    "",
                    f"Bugcrowd link: [{links}]({links})",
                ],
            )
            mitigation = entry["attributes"]["remediation_advice"]
            steps_to_reproduce = entry["attributes"]["description"]
            unique_id_from_tool = entry["id"]

            finding = Finding(
                test=test,
                title=textwrap.shorten(title, width=511, placeholder="..."),
                date=date,
                severity=self.convert_severity(bugcrowd_severity),
                description=description,
                mitigation=mitigation,
                steps_to_reproduce=steps_to_reproduce,
                active=self.is_active(bugcrowd_state),
                verified=self.is_verified(bugcrowd_state),
                false_p=self.is_false_p(bugcrowd_state),
                out_of_scope=self.is_out_of_scope(bugcrowd_state),
                is_mitigated=self.is_mitigated(bugcrowd_state),
                static_finding=False,
                dynamic_finding=True,
                unique_id_from_tool=unique_id_from_tool,
                references=links,
            )

            if self.is_not_applicable(bugcrowd_state):
                # From Bugcrowd - Not Applicable: A submission that you reject because it does not apply to your application.
                # Because of this, setting finding to inactive and to Informational
                finding.active = False
                finding.severity = "Info"

            if bug_endpoint:
                try:
                    bug_endpoint.clean()
                    try:
                        finding.unsaved_endpoints = [bug_endpoint]
                    except Exception as e:
                        logger.error(
                            f"{bug_endpoint} bug url from bugcrowd failed to parse to endpoint, error= {e}",
                        )
                except ValidationError:
                    logger.error(
                        f"Broken Bugcrowd endpoint {bug_endpoint.host} was skipped.",
                    )

            findings.append(finding)

        return findings

    def get_created_date(self, date):
        """Get the date of when a finding was created"""
        return self.convert_log_timestamp(date)

    def get_latest_update_date(self, log):
        """Get the date of the last time a finding was updated"""
        last_index = len(log) - 1
        entry = log[last_index]
        return self.convert_log_timestamp(entry["timestamp"])

    def include_finding(self, entry):
        """Determine whether this finding should be imported to DefectDojo"""
        # Valid states from the Bugcrowd API
        # "new" "out-of-scope" "not-applicable" "not-reproducible" "triaged" "unresolved" "resolved" "informational"

        allowed_states = [
            "new",  # Finding from a previous pentest
            "out_of_scope",  # Fix for finding is being verified
            "not_applicable",  # Finding is a duplicate within the pentest
            "not_reproducible",  # Finding is found to be a false positive
            "triaged",  # Finding is verified and valid
            "unresolved",  # The finding is not yet verified by the pentest team
            "resolved",  # Finding is out of the scope of the pentest
            "informational",  # The finding is not yet verified by the pentest team
        ]

        if entry["attributes"]["state"] in allowed_states:
            return True
        msg = (
            "{} not in allowed bugcrowd submission states".format(
                entry["attributes"]["state"],
            )
        )
        raise ValueError(msg)

    def convert_log_timestamp(self, timestamp):
        """Convert a log entry's timestamp to a DefectDojo date"""
        date_obj = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
        return date_obj.strftime("%Y-%m-%d")

    def convert_severity(self, bugcrowd_severity):
        """Convert severity value"""
        if bugcrowd_severity == 5:
            return "Info"
        if bugcrowd_severity == 4:
            return "Low"
        if bugcrowd_severity == 3:
            return "Medium"
        if bugcrowd_severity == 2:
            return "High"
        if bugcrowd_severity == 1:
            return "Critical"
        return "Info"

    def is_active(self, bugcrowd_state):
        return (bugcrowd_state == "unresolved") or not (
            self.is_mitigated(bugcrowd_state)
            or self.is_false_p(bugcrowd_state)
            or self.is_out_of_scope(bugcrowd_state)
            or bugcrowd_state == "not_reproducible"
            or bugcrowd_state == "informational"
        )

    # From https://docs.bugcrowd.com/customers/submission-management/submission-status/
    # Status Options
    # There are three categories of statuses: open, accepted, and rejected. Within each category are the following statuses:

    # Open
    # New: A submission that has not been reviewed or assigned a status.
    # Triaged: A submission that has been confirmed valid and unique by the Bugcrowd ASE team and is ready for the customer to accept.

    # Accepted
    # Unresolved: A valid submission that needs to be fixed. Typically, you should reward a submission at this point in the process.
    # Resolved: A valid submission that has been fixed.
    # Informational: A submission that is reproducible but will not be fixed. Use this if the submission is a best practice issue but
    # will not be fixed, a minor priority issue, or if you already have a mitigation.

    # Rejected
    # Out of Scope: A submission you reject because it is not in scope with the criteria outlined in the bounty program.
    # Not Reproducible: A submission you reject because you cannot reproduce it based on the information you have.
    # Not Applicable: A submission that you reject because it does not apply to your application.

    def is_duplicate(self, bugcrowd_state):
        return bugcrowd_state == "duplicate"

    def is_false_p(self, bugcrowd_state):
        return bugcrowd_state == "not_reproducible"

    def is_mitigated(self, bugcrowd_state):
        return bugcrowd_state == "resolved"

    def is_out_of_scope(self, bugcrowd_state):
        return bugcrowd_state == "out_of_scope"

    def is_not_applicable(self, bugcrowd_state):
        return bugcrowd_state == "not_applicable"

    def is_verified(self, bugcrowd_state):
        return bugcrowd_state == "triaged" or (
            bugcrowd_state != "new" and bugcrowd_state != "triaging"
        )
