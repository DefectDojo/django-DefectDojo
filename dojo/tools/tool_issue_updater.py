from dojo.celery import app

from dojo.decorators import (dojo_async_task, dojo_model_from_id,
                             dojo_model_to_id)
from dojo.tools.api_sonarqube.parser import SCAN_SONARQUBE_API
from dojo.tools.neuvector.parser import NEUVECTOR_SCAN_NAME


def async_tool_issue_update(finding, *args, **kwargs):
    if is_tool_issue_updater_needed(finding):
        tool_issue_updater(finding)


def is_tool_issue_updater_needed(finding, *args, **kwargs):
    test_type = finding.test.test_type
    return test_type.name == SCAN_SONARQUBE_API


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def tool_issue_updater(finding, *args, **kwargs):

    test_type = finding.test.test_type

    if test_type.name == SCAN_SONARQUBE_API:
        from dojo.tools.api_sonarqube.updater import SonarQubeApiUpdater
        SonarQubeApiUpdater().update_sonarqube_finding(finding)


@dojo_async_task
@app.task
def update_findings_from_source_issues(**kwargs):
    from dojo.tools.api_sonarqube.updater_from_source import \
        SonarQubeApiUpdaterFromSource

    findings = SonarQubeApiUpdaterFromSource().get_findings_to_update()

    for finding in findings:
        SonarQubeApiUpdaterFromSource().update(finding)


def async_tool_ra_update(finding, *args, **kwargs):
    if is_tool_ra_update_needed(finding):
        tool_ra_update(finding)


def async_tool_ra_remove(finding, *args, **kwargs):
    if is_tool_ra_update_needed(finding):
        tool_ra_remove(finding)


def is_tool_ra_update_needed(finding, *args, **kwargs):
    test_type = finding.test.test_type
    return test_type.name == NEUVECTOR_SCAN_NAME


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def tool_ra_update(finding, *args, **kwargs):
    test_type = finding.test.test_type
    if test_type.name == NEUVECTOR_SCAN_NAME:
        from dojo.tools.neuvector_api.updater import NeuVectorApiUpdater
        NeuVectorApiUpdater().update_risk_acceptance(finding)


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def tool_ra_remove(finding, *args, **kwargs):
    test_type = finding.test.test_type
    if test_type.name == NEUVECTOR_SCAN_NAME:
        from dojo.tools.neuvector_api.updater import NeuVectorApiUpdater
        NeuVectorApiUpdater().check_remove_risk_acceptance(finding)
