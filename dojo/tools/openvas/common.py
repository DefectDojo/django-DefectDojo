import hashlib
import os
from dataclasses import dataclass

from dojo.models import Finding

OPENVAS_SEVERITY_OVERWRITE = os.environ.get("OPENVAS_SEVERITY_OVERWRITE", "False").lower() in {"true", 1}


@dataclass
class OpenVASFindingAuxData:

    """Dataclass to contain all information added later to description"""

    qod: str = ""


def is_valid_severity(severity):
    valid_severity = ("Info", "Low", "Medium", "High", "Critical")
    return severity in valid_severity


def update_description(finding: Finding, aux_info: OpenVASFindingAuxData):
    if aux_info.qod:
        finding.description += f"\n**QoD**: {aux_info.qod}"


def deduplicate(dupes: dict[str, Finding], finding: Finding):
    """Combine multiple openvas findings into one defectdojo finding with multiple endpoints"""
    finding_hash = generate_openvas_finding_hash(finding)
    # set for use in global deduplication
    finding.unique_id_from_tool = finding_hash

    if finding_hash not in dupes:
        dupes[finding_hash] = finding
    else:
        # openvas does not combine multiple findings into one e.g
        # a vunerability in the java runtime may be reported 2 times
        # if 2 vulnerable java runtimes are present on the host
        # and the only way do differantiate this findings are the specific results (mapped to references by the parser)
        # but we cannot hash this field as it can contain data that changes between scans e.g timestamps
        # we therfore combine them because duplicates during reimport cause
        # https://github.com/DefectDojo/django-DefectDojo/issues/3958
        org = dupes[finding_hash]
        if org.references != finding.references:
            org.references += "\n---------------------------------------\n"
            org.references += f"**Endpoint**: {finding.unsaved_endpoints[0].host}\n"
            org.references += finding.references

        # combine identical findings on different hosts into one with multiple hosts
        endpoint = finding.unsaved_endpoints[0]
        if endpoint not in org.unsaved_endpoints:
            org.unsaved_endpoints += finding.unsaved_endpoints


def generate_openvas_finding_hash(finding: Finding):
    """Generate a hash for a finding that is used for deduplication of findings inside the current report"""
    endpoint = finding.unsaved_endpoints[0]
    hash_data = [
        str(endpoint.protocol),
        str(endpoint.userinfo),
        str(endpoint.port),
        str(endpoint.path),
        str(endpoint.fragment),
        finding.title,
        finding.description,
        finding.severity,
    ]
    return hashlib.sha256("|".join(hash_data).encode("utf-8")).hexdigest()
