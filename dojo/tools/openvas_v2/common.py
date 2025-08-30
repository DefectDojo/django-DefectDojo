import hashlib
import os
from dataclasses import dataclass

from dojo.models import Finding

OPENVAS_SEVERITY_OVERWRITE = os.environ.get("OPENVAS_SEVERITY_OVERWRITE", "False").lower() in {"true", 1}


@dataclass
class OpenVASFindingAuxData:
    """Dataclass to contain all information added later to fields"""

    summary: str = ""
    qod: str = ""
    openvas_result: str = ""


def is_valid_severity(severity):
    valid_severity = ("Info", "Low", "Medium", "High", "Critical")
    return severity in valid_severity


def update_finding(finding: Finding, aux_info: OpenVASFindingAuxData):
    """Update finding description"""
    if aux_info.openvas_result:
        finding.steps_to_reproduce = aux_info.openvas_result
    if aux_info.summary:
        finding.description += f"\n**Summary**: {aux_info.summary}"
    if aux_info.qod:
        finding.description += f"\n**QoD**: {aux_info.qod}"


def deduplicate(dupes: dict[str, Finding], finding: Finding):
    """Combine multiple openvas findings into one defectdojo finding with multiple endpoints"""
    finding_hash = dedup_finding_hash(finding)
    # deliberately missuse unique_id_from_tool to save some original values
    finding.unique_id_from_tool = id_from_tool_finding_hash(finding)

    if finding_hash not in dupes:
        dupes[finding_hash] = finding
    else:
        # OpenVas does not combine multiple findings into one
        # e.g if 2 vulnerable java runtimes are present on the host this is reported as 2 finding.
        # The only way do differantiate theese findings when they are based on the same vulnerabilty
        # is the data in mapped to steps to reproduce.
        # However we cannot hash this field as it can contain data that changes between scans
        # e.g timestamps or packet ids
        # we therfore combine them into one defectdojo finding because duplicates during reimport cause
        # https://github.com/DefectDojo/django-DefectDojo/issues/3958
        org = dupes[finding_hash]
        if org.steps_to_reproduce != finding.steps_to_reproduce:
            if "Endpoint" in org.steps_to_reproduce:
                org.steps_to_reproduce += "\n---------------------------------------\n"
                org.steps_to_reproduce += f"**Endpoint**: {finding.unsaved_endpoints[0].host}\n"
                org.steps_to_reproduce += finding.steps_to_reproduce
            else:
                tmp = org.steps_to_reproduce
                org.steps_to_reproduce = f"**Endpoint**: {org.unsaved_endpoints[0].host}\n"
                org.steps_to_reproduce += tmp

        # combine identical findings on different hosts into one with multiple hosts
        endpoint = finding.unsaved_endpoints[0]
        if endpoint not in org.unsaved_endpoints:
            org.unsaved_endpoints += finding.unsaved_endpoints


def id_from_tool_finding_hash(finding: Finding):
    """Generate a hash that complements final hash generating outside of this parser"""
    endpoint = finding.unsaved_endpoints[0]
    hash_data = [
        str(endpoint.protocol),
        str(endpoint.userinfo),
        str(endpoint.port),  # keep findings on different port seperate as it may be different applications
        str(endpoint.path),
        str(endpoint.fragment),
        finding.severity,  # allows changing severity of finding after import
    ]
    return hashlib.sha256("|".join(hash_data).encode("utf-8")).hexdigest()


def dedup_finding_hash(finding: Finding):
    """Generate a hash for a finding that is used for deduplication of findings inside the current report"""
    endpoint = finding.unsaved_endpoints[0]
    hash_data = [
        str(endpoint.protocol),
        str(endpoint.userinfo),
        str(endpoint.port),
        str(endpoint.path),
        str(endpoint.fragment),
        finding.title,
        finding.vuln_id_from_tool,
        finding.severity,
    ]
    return hashlib.sha256("|".join(hash_data).encode("utf-8")).hexdigest()
