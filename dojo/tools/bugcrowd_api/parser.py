import json
import textwrap
from datetime import datetime
from dojo.models import Endpoint, Finding
from dojo.tools.bugcrowd_api.importer import BugcrowdApiImporter
import re
import dateutil.parser
import logging
from django.core.exceptions import ValidationError


SCAN_BUGCROWD_API = "Bugcrowd API Import"

pattern_title_authorized = re.compile(r"^[a-zA-Z0-9_\s+-.]*$")

logger = logging.getLogger(__name__)


class BugcrowdApiParser(object):
    """
    Import from Bugcrowd API /submissions
    """

    def get_scan_types(self):
        return [SCAN_BUGCROWD_API]

    def get_label_for_scan_types(self, scan_type):
        return SCAN_BUGCROWD_API

    def get_description_for_scan_types(self, scan_type):
        return "Bugcrowd submissions can be directly imported using the Bugcrowd API. An API Scan Configuration has to be setup in the Product."

    def requires_file(self, scan_type):
        return False

    def requires_tool_type(self, scan_type):
        return "Bugcrowd API"

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
                    str(config.service_key_1), entry["links"]["self"]
                )
            if api_scan_config is not None:
                links = "https://tracker.bugcrowd.com/{}{}".format(
                    str(api_scan_config.service_key_1), entry["links"]["self"]
                )
            else:
                links = None
                if "links" in entry and "self" in entry["links"]:
                    links = entry["links"]["self"]

            bugcrowd_state = entry["attributes"]["state"]
            bugcrowd_duplicate = entry["attributes"]["duplicate"]
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
                    if "://" in entry["attributes"]["bug_url"]:  # is the host full uri?
                        bug_endpoint = Endpoint.from_uri(
                            entry["attributes"]["bug_url"].strip()
                        )
                        # can raise exception if the host is not valid URL
                    else:
                        bug_endpoint = Endpoint.from_uri(
                            "//" + entry["attributes"]["bug_url"].strip()
                        )
                        # can raise exception if there is no way to parse the host
                except ValidationError:  # We don't want to fail the whole import just for 1 error in the bug_url
                    logger.error(
                        "Error parsing bugcrowd bug_url : {}".format(
                            entry["attributes"]["bug_url"].strip()
                        )
                    )
                bug_url = entry["attributes"]["bug_url"]

            description = "\n".join(
                [
                    entry["attributes"]["description"],
                    "",
                    "Bugcrowd details:",
                    f"- Severity: P{ bugcrowd_severity }",
                    f"- Bug Url: [{bug_url}]({ bug_url })",
                    "",
                    f"Bugcrowd link: [{links}]({links})",
                ]
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
                risk_accepted=self.is_risk_accepted(bugcrowd_state),
                is_mitigated=self.is_mitigated(bugcrowd_state),
                static_finding=False,
                dynamic_finding=True,
                unique_id_from_tool=unique_id_from_tool,
                references=links,
            )
            if bug_endpoint:
                try:
                    bug_endpoint.clean()
                    try:
                        finding.unsaved_endpoints = [bug_endpoint]
                    except Exception as e:
                        logger.error(
                            "{} bug url from bugcrowd failed to parse to endpoint, error= {}".format(
                                str(bug_endpoint), e
                            )
                        )
                except ValidationError:
                    logger.error(
                        "Broken Bugcrowd endpoint {} was skipped.".format(
                            bug_endpoint.host
                        )
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
        else:
            raise ValueError(
                "{} not in allowed bugcrowd submission states".format(
                    entry["attributes"]["state"]
                )
            )

    def convert_log_timestamp(self, timestamp):
        """Convert a log entry's timestamp to a DefectDojo date"""
        date_obj = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
        return date_obj.strftime("%Y-%m-%d")

    def convert_severity(self, bugcrowd_severity):
        """Convert severity value"""
        if bugcrowd_severity == 5:
            return "Info"
        elif bugcrowd_severity == 4:
            return "Low"
        elif bugcrowd_severity == 3:
            return "Medium"
        elif bugcrowd_severity == 2:
            return "High"
        elif bugcrowd_severity == 1:
            return "Critical"
        else:
            return "Info"

    def is_active(self, bugcrowd_state):
        return (bugcrowd_state == "unresolved") or not (
            self.is_mitigated(bugcrowd_state)
            or self.is_false_p(bugcrowd_state)
            or self.is_out_of_scope(bugcrowd_state)
            or self.is_risk_accepted(bugcrowd_state)
            or bugcrowd_state == "not_reproducible"
            or bugcrowd_state == "informational"
        )

    def is_duplicate(self, bugcrowd_state):
        return bugcrowd_state == "duplicate"

    def is_false_p(self, bugcrowd_state):
        return bugcrowd_state == "not-reproducible"

    def is_mitigated(self, bugcrowd_state):
        return bugcrowd_state == "resolved"

    def is_out_of_scope(self, bugcrowd_state):
        return bugcrowd_state == "out_of_scope"

    def is_risk_accepted(self, bugcrowd_state):
        return bugcrowd_state == "not_applicable"

    def is_verified(self, bugcrowd_state):
        return bugcrowd_state == "triaged" or (
            bugcrowd_state != "new" and bugcrowd_state != "triaging"
        )
