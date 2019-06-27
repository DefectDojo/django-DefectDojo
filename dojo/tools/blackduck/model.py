from dataclasses import dataclass
from typing import Set


@dataclass
class BlackduckFinding:
    vuln_id: str
    description: str
    security_risk: str
    impact: str
    vuln_source: str
    url: str
    channel_version_origin_id: str
    published_date: str
    updated_date: str
    base_score: str
    exploitability: str
    remediation_status: str
    remediation_target_date: str
    remediation_actual_date: str
    remediation_comment: str
    locations: Set[str]
