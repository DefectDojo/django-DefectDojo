from dojo.tools import SCAN_SONARQUBE_API


def async_tool_issue_update(finding, *args, **kwargs):
    if is_tool_issue_updater_needed(finding):
        from dojo.tasks import async_tool_issue_updater
        async_tool_issue_updater.delay(finding)


def is_tool_issue_updater_needed(finding, *args, **kwargs):
    test_type = finding.test.test_type
    return test_type.name == SCAN_SONARQUBE_API


def tool_issue_updater(finding, *args, **kwargs):

    test_type = finding.test.test_type

    if test_type.name == SCAN_SONARQUBE_API:
        from dojo.tools.sonarqube_api.updater import SonarQubeApiUpdater
        SonarQubeApiUpdater().update_sonarqube_finding(finding)


def update_findings_from_source_issues():
    from dojo.tools.sonarqube_api.updater_from_source import SonarQubeApiUpdaterFromSource

    findings = SonarQubeApiUpdaterFromSource().get_findings_to_update()

    for finding in findings:
        SonarQubeApiUpdaterFromSource().update(finding)
