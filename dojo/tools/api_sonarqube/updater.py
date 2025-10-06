import logging
from collections import deque

from dojo.models import Sonarqube_Issue_Transition

from .importer import SonarQubeApiImporter

logger = logging.getLogger(__name__)


class SonarQubeApiUpdater:

    """
    This class updates in SonarQube, a SonarQube issue previously imported as a DefectDojo Findings.
     This class maps the finding status to a SQ issue status and later on it transitions the issue
     properly to a consistent status.
     This way, findings marked as resolved, false positive or accepted in DefectDojo won't reappear
     in future imports of SonarQube Scanner.
    """

    MAPPING_SONARQUBE_STATUS_TRANSITION = [
        {"from": ["OPEN", "REOPENED"], "to": "REOPENED", "transition": None},
        {
            "from": ["OPEN", "REOPENED"],
            "to": "CONFIRMED",
            "transition": "confirm",
        },
        {"from": ["CONFIRMED"], "to": "REOPENED", "transition": "unconfirm"},
        {
            "from": ["OPEN", "REOPENED", "CONFIRMED"],
            "to": "RESOLVED / FIXED",
            "transition": "resolve",
        },
        {
            "from": ["OPEN", "REOPENED", "CONFIRMED"],
            "to": "RESOLVED / WONTFIX",
            "transition": "wontfix",
        },
        {
            "from": ["OPEN", "REOPENED", "CONFIRMED"],
            "to": "RESOLVED / FALSE-POSITIVE",
            "transition": "falsepositive",
        },
        {
            "from": [
                "RESOLVED / FIXED",
                "RESOLVED / WONTFIX",
                "RESOLVED / FALSE-POSITIVE",
            ],
            "to": "REOPENED",
            "transition": "reopen",
        },
    ]

    MAPPING_SONARQUBE_HOTSPOT_STATUS_TRANSITION = [
        {
            "from": ["TO_REVIEW"],
            "to": "RESOLVED / FALSE-POSITIVE",
            "transition": "REVIEWED",
            "resolution": "SAFE",
        },
        {
            "from": ["TO_REVIEW"],
            "to": "RESOLVED / FIXED",
            "transition": "REVIEWED",
            "resolution": "FIXED",
        },
                {
            "from": ["TO_REVIEW"],
            "to": "RESOLVED / WONTFIX",
            "transition": "REVIEWED",
            "resolution": "ACKNOWLEDGED",
        },
        {
            "from": ["REVIEWED"],
            "to": "OPEN",
            "transition": "TO_REVIEW",
            "resolution": None,
        },
        {
            "from": ["REVIEWED"],
            "to": "REOPENED",
            "transition": "TO_REVIEW",
            "resolution": None,
        },
        {
            "from": ["REVIEWED"],
            "to": "CONFIRMED",
            "transition": "TO_REVIEW",
            "resolution": None,
        },
    ]

    @staticmethod
    def get_sonarqube_status_for(finding):
        target_status = None
        if finding.false_p:
            target_status = "RESOLVED / FALSE-POSITIVE"
        elif finding.mitigated or finding.is_mitigated:
            target_status = "RESOLVED / FIXED"
        elif finding.risk_accepted:
            target_status = "RESOLVED / WONTFIX"
        elif finding.active:
            target_status = "CONFIRMED" if finding.verified else "REOPENED"
        return target_status

    def get_sonarqube_required_transitions_for(
        self, current_status, target_status, is_hotspot):
        # If current and target is the same... do nothing
        if current_status == target_status:
            return None

        # Select the appropriate mapping based on issue type
        mapping = (
            self.MAPPING_SONARQUBE_HOTSPOT_STATUS_TRANSITION
            if is_hotspot
            else self.MAPPING_SONARQUBE_STATUS_TRANSITION
        )

        # Check if there is at least one transition from current_status...
        if not [
            x
            for x in mapping
            if current_status in x.get("from")
        ]:
            return None

        # Starting from target_status... find out possible origin statuses that
        # can transition to target_status
        transitions = [
            x
            for x in mapping
            if target_status == x.get("to")
        ]
        if transitions:
            for transition in transitions:
                # There is a direct transition from current status...
                if current_status in transition.get("from"):
                    t = transition.get("transition")
                    if is_hotspot:
                        return [{"status": t, "resolution": transition.get("resolution")}] if t else None
                    return [t] if t else None

            # Handle complex transitions for regular issues
            if not is_hotspot:
                # We have the last transition to get to our target status but there
                # is no direct transition
                transitions_result = deque()
                transitions_result.appendleft(transitions[0].get("transition"))

                # Find out previous transitions that would finish in any FROM of a
                # previous to use as target
                for transition in transitions:
                    for t_from in transition.get("from"):
                        possible_transition = (
                            self.get_sonarqube_required_transitions_for(
                                current_status, t_from, is_hotspot,
                            )
                        )
                        if possible_transition:
                            transitions_result.extendleft(possible_transition)
                            return list(transitions_result)
            else:
                # SQ code is too complicated for ISSUES, there is no such thing for HOTSPOTS,
                # there are only 2 states: TO_REVIEW and REVIEWED
                transitions_result = deque()
                transitions_result.appendleft(
                    {"status": transitions[0].get("transition"),
                    "resolution": transitions[0].get("resolution")},
                )
                return list(transitions_result)
        return None

    def update_sonarqube_finding(self, finding):
        sonarqube_issue = finding.sonarqube_issue
        if not sonarqube_issue:
            return

        logger.debug(
            "Checking if finding '%s' needs to be updated in SonarQube", finding,
        )

        client, _ = SonarQubeApiImporter.prepare_client(finding.test)
        # we don't care about config, each finding knows which config was used
        # during import

        target_status = self.get_sonarqube_status_for(finding)
        is_hotspot = sonarqube_issue.type == "SECURITY_HOTSPOT"

        issue = client.get_hotspot(sonarqube_issue.key) if is_hotspot else client.get_issue(sonarqube_issue.key)

        # Issue does not exist (could have disappeared in SQ because a previous scan resolved it)
        if not issue:
            return

        if is_hotspot:
            current_status = issue.get("status")
        elif issue.get("resolution"):
            current_status = "{} / {}".format(issue.get("status"), issue.get("resolution"))
        else:
            current_status = issue.get("status")

        # Get required transitions
        transitions = self.get_sonarqube_required_transitions_for(
            current_status, target_status, is_hotspot=is_hotspot,
        )

        if not transitions:
            logger.debug(
                "--> SQ Current status: %s. Current target status: %s", current_status, target_status,
            )
            return

        logger.debug(
                f"Updating finding '{finding}' transition {current_status} -> {target_status} in SonarQube",
            )

        # Apply transitions
        for transition in transitions:
            if is_hotspot:
                client.transition_hotspot(sonarqube_issue.key,
                            status=transition["status"],
                            resolution=transition["resolution"])
            else:
                client.transition_issue(sonarqube_issue.key, transition)

        # Track that Defect Dojo has updated the SonarQube issue
        Sonarqube_Issue_Transition.objects.create(
            sonarqube_issue=finding.sonarqube_issue,
            # not sure if this is needed, but looks like the original author decided to send display status
            # to sonarqube we changed Accepted into Risk Accepted, but we change it back to be sure we don't
            # break the integration
            finding_status=finding.status().replace(
            "Risk Accepted", "Accepted",
            )
            if finding.status()
            else finding.status(),
            sonarqube_status=current_status,
            transitions=",".join(transition["status"] if is_hotspot else transition for transition in transitions),
        )
