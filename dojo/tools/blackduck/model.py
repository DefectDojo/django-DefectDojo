from typing import NamedTuple


class BlackduckFinding(NamedTuple):
    vuln_id: str
    description: str
    security_risk: str
    impact: str
    component_name: str
    component_version: str
    vuln_source: str
    url: str
    channel_version_origin_id: str
    component_origin_id: str
    published_date: str
    updated_date: str
    base_score: str
    exploitability: str
    remediation_status: str
    remediation_target_date: str
    remediation_actual_date: str
    remediation_comment: str
    locations: str
