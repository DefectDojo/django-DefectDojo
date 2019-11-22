__author__ = 'jay7958'

SCAN_GENERIC_FINDING = 'Generic Findings Import'
SCAN_SONARQUBE_API = 'SonarQube API Import'


def requires_file(scan_type):
    return (
        scan_type and scan_type != SCAN_SONARQUBE_API
    )


def handles_active_verified_statuses(scan_type):
    return scan_type in [
        SCAN_GENERIC_FINDING, SCAN_SONARQUBE_API
    ]
