from dojo.tools import SCAN_SONARQUBE_API


def tool_issue_updater(finding, *args, **kwargs):

    test_type = finding.test.test_type

    if test_type.name == SCAN_SONARQUBE_API:
        from dojo.tools.sonarqube_api.updater import SonarQubeApiUpdater
        SonarQubeApiUpdater().update_sonarqube_finding(finding)
