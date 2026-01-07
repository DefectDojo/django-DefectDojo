import logging

import pghistory

from dojo.celery import app
from dojo.celery_dispatch import dojo_dispatch_task
from dojo.models import Finding
from dojo.tools.api_sonarqube.parser import SCAN_SONARQUBE_API
from dojo.tools.api_sonarqube.updater import SonarQubeApiUpdater
from dojo.tools.api_sonarqube.updater_from_source import SonarQubeApiUpdaterFromSource
from dojo.utils import get_object_or_none

logger = logging.getLogger(__name__)


def async_tool_issue_update(finding, *args, **kwargs):
    if is_tool_issue_updater_needed(finding):
        dojo_dispatch_task(tool_issue_updater, finding.id)


def is_tool_issue_updater_needed(finding, *args, **kwargs):
    test_type = finding.test.test_type
    return test_type.name == SCAN_SONARQUBE_API


@app.task
def tool_issue_updater(finding_id, *args, **kwargs):
    finding = get_object_or_none(Finding, id=finding_id)
    if not finding:
        logger.warning("Finding with id %s does not exist, skipping tool_issue_updater", finding_id)
        return

    test_type = finding.test.test_type

    if test_type.name == SCAN_SONARQUBE_API:
        SonarQubeApiUpdater().update_sonarqube_finding(finding)


@app.task
def update_findings_from_source_issues(**kwargs):
    # Wrap with pghistory context for audit trail
    with pghistory.context(source="sonarqube_sync"):
        findings = SonarQubeApiUpdaterFromSource().get_findings_to_update()

        for finding in findings:
            SonarQubeApiUpdaterFromSource().update(finding)
