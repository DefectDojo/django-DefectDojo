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
    finding.description += f"\n**QoD**: {aux_info.qod}"


def deduplicate(dupes: dict[str, Finding], finding: Finding):
    key = generate_openvas_finding_hash(finding)
    # set for use in global deduplication
    finding.unique_id_from_tool = key

    if key not in dupes:
        dupes[key] = finding
    else:
        # openvas does not combine findings of the same type
        # that are listed as multiple findings on the same host e.g
        # a vunerability in the java runtime may be reported 2 times
        # if 2 vulnerable java runtimes are present on the host
        # and the only way do differantiate this findings are the specific results (mapped to references by the parser)
        # but we cannot hash this field as this field can contain data that changes between scans e.g timestamps
        # we therfore combine them because duplicates during reimport cause
        # https://github.com/DefectDojo/django-DefectDojo/issues/3958
        org = dupes[key]
        if org.references != finding.references:
            org.references += "\n---------------------------------------\n"
            org.references += finding.references


def generate_openvas_finding_hash(finding: Finding):
    """Generate a hash for a finding that is used for deduplication of findings inside the current report"""
    hash_data = [str(finding.unsaved_endpoints[0]), finding.title, finding.description, finding.severity]
    return hashlib.sha256("|".join(hash_data).encode("utf-8")).hexdigest()
