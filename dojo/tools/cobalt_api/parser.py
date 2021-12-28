import json
import textwrap
from datetime import datetime
from dojo.models import Endpoint, Finding
from dojo.tools.cobalt_api.importer import CobaltApiImporter


SCAN_COBALTIO_API = 'Cobalt.io API Import'


class CobaltApiParser(object):
    """
    Import from Cobalt.io API /findings
    """

    def get_scan_types(self):
        return [SCAN_COBALTIO_API]

    def get_label_for_scan_types(self, scan_type):
        return SCAN_COBALTIO_API

    def get_description_for_scan_types(self, scan_type):
        return "Cobalt.io findings can be directly imported using the Cobalt.io API. An API Scan Configuration has to be setup in the Product."

    def requires_file(self, scan_type):
        return False

    def requires_tool_type(self, scan_type):
        return 'Cobalt.io'

    def get_findings(self, file, test):
        if file is None:
            data = CobaltApiImporter().get_findings(test)
        else:
            data = json.load(file)

        findings = []
        for entry in data["data"]:
            resource = entry["resource"]
            links = entry["links"]
            if not self.include_finding(resource):
                continue

            cobalt_state = resource["state"]
            cobalt_severity = resource["severity"]
            cobalt_log = resource["log"]

            title = resource["title"]
            date = self.get_created_date(cobalt_log)
            description = "\n".join(
                [
                    resource["description"],
                    "",
                    "Cobalt.io details:",
                    f"- Impact: {resource['impact']}",
                    f"- Likelihood: {resource['likelihood']}",
                    "",
                    "Cobalt.io link:",
                    links["ui"]["url"],
                ]
            )
            mitigation = resource["suggested_fix"]
            steps_to_reproduce = resource["proof_of_concept"]
            endpoints = resource["affected_targets"]
            last_status_update = self.get_latest_update_date(cobalt_log)
            unique_id_from_tool = resource["id"]

            finding = Finding(
                test=test,
                title=textwrap.shorten(title, width=511, placeholder="..."),
                date=date,
                severity=self.convert_severity(cobalt_severity),
                description=description,
                mitigation=mitigation,
                steps_to_reproduce=steps_to_reproduce,
                active=self.is_active(cobalt_state),
                verified=self.is_verified(cobalt_state),
                false_p=self.is_false_p(cobalt_state),
                duplicate=self.is_duplicate(cobalt_state),
                out_of_scope=self.is_out_of_scope(cobalt_state),
                risk_accepted=self.is_risk_accepted(cobalt_state),
                is_mitigated=self.is_mitigated(cobalt_state),
                last_status_update=last_status_update,
                static_finding=False,
                dynamic_finding=True,
                unique_id_from_tool=unique_id_from_tool)
            finding.unsaved_endpoints = self.convert_endpoints(endpoints)

            findings.append(finding)

        return findings

    def get_created_date(self, log):
        """Get the date of when a finding was created"""
        for entry in log:
            if entry["action"] == "created":
                return self.convert_log_timestamp(entry["timestamp"])

        return None

    def get_latest_update_date(self, log):
        """Get the date of the last time a finding was updated"""
        last_index = len(log) - 1
        entry = log[last_index]
        return self.convert_log_timestamp(entry["timestamp"])

    def include_finding(self, resource):
        """Determine whether this finding should be imported to DefectDojo"""
        allowed_states = [
            "carried_over",  # Finding from a previous pentest
            "check_fix",     # Fix for finding is being verified
            "duplicate",     # Finding is a duplicate within the pentest
            "invalid",       # Finding is found to be a false positive
            "need_fix",      # Finding is verified and valid
            "new",           # The finding is not yet verified by the pentest team
            "out_of_scope",  # Finding is out of the scope of the pentest
            "triaging",      # The finding is not yet verified by the pentest team
            "valid_fix",     # Fix for finding has been varified
            "wont_fix",      # Risk of finding has been accepted
        ]

        if resource["state"] in allowed_states:
            return True
        else:
            return False

    def convert_endpoints(self, affected_targets):
        """Convert Cobalt affected_targets into DefectDojo endpoints"""
        endpoints = []
        for affected_target in affected_targets:
            endpoint = Endpoint.from_uri(affected_target)
            endpoints.append(endpoint)
        return endpoints

    def convert_log_timestamp(self, timestamp):
        """Convert a log entry's timestamp to a DefectDojo date"""
        date_obj = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
        return date_obj.strftime("%Y-%m-%d")

    def convert_severity(self, cobalt_severity):
        """Convert severity value"""
        if cobalt_severity == "low":
            return "Low"
        elif cobalt_severity == "medium":
            return "Medium"
        elif cobalt_severity == "high":
            return "High"
        else:
            return "Info"

    def is_active(self, cobalt_state):
        return not self.is_mitigated(cobalt_state) \
            and not self.is_false_p(cobalt_state) \
            and not self.is_out_of_scope(cobalt_state)

    def is_duplicate(self, cobalt_state):
        return cobalt_state == "duplicate"

    def is_false_p(self, cobalt_state):
        return cobalt_state == "invalid"

    def is_mitigated(self, cobalt_state):
        return cobalt_state == "valid_fix"

    def is_out_of_scope(self, cobalt_state):
        return cobalt_state == "out_of_scope"

    def is_risk_accepted(self, cobalt_state):
        return cobalt_state == "wont_fix"

    def is_verified(self, cobalt_state):
        return cobalt_state != "new" and cobalt_state != "triaging"
