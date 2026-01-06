import hashlib
from dataclasses import dataclass

from dojo.models import Endpoint, Finding


@dataclass
class OpenVASFindingAuxData:

    """Dataclass to contain all information added later to a finding"""

    references: list[str]
    summary: str = ""
    qod: str = ""
    openvas_result: str = ""
    fallback_cvss_score: float | None = None


def setup_finding(test) -> tuple[Finding, OpenVASFindingAuxData]:
    """Base setup and init for findings and auxiliary data"""
    finding = Finding(test=test, dynamic_finding=True, static_finding=False, severity="Info", nb_occurences=1, cwe=None)
    finding.unsaved_vulnerability_ids = []
    finding.unsaved_endpoints = [Endpoint()]

    aux_info = OpenVASFindingAuxData([])

    return finding, aux_info


def is_valid_severity(severity: str) -> bool:
    valid_severity = ("Info", "Low", "Medium", "High", "Critical")
    return severity in valid_severity


def cleanup_openvas_text(text: str) -> str:
    """Removes unnessesary defectojo newlines"""
    return text.replace("\n  ", " ")


def escape_restructured_text(text: str) -> str:
    """Changes text so that restructured text symbols are not interpreted"""
    # OpenVAS likes to include markdown like tables in some fields
    # Defectdojo uses reStructuredText which causes them to be rendered wrong
    text = text.replace("```", "")
    text = text.replace("```", "")
    return f"```\n{text}\n```"


def postprocess_finding(finding: Finding, aux_info: OpenVASFindingAuxData):
    """Update finding with AuxData content"""
    if aux_info.openvas_result:
        finding.steps_to_reproduce = escape_restructured_text(cleanup_openvas_text(aux_info.openvas_result))
    if aux_info.summary:
        finding.description += f"\n**Summary**: {cleanup_openvas_text(aux_info.summary)}"
    if aux_info.qod:
        finding.description += f"\n**QoD**: {aux_info.qod}"
    if len(aux_info.references) > 0:
        finding.references = "\n".join(["- " + ref for ref in aux_info.references])
    # fallback in case no cvss version is detected
    if aux_info.fallback_cvss_score and not finding.cvssv3_score and not finding.cvssv4_score:
        finding.cvssv3_score = aux_info.fallback_cvss_score

    # heuristic for fixed-available detection
    if finding.mitigation:
        search_terms = ["Update to version", "The vendor has released updates"]
        if any(text in finding.mitigation for text in search_terms):
            finding.fix_available = True


def deduplicate(dupes: dict[str, Finding], finding: Finding):
    """Combine multiple openvas findings into one defectdojo finding with potentially multiple endpoints"""
    finding_hash = gen_finding_hash(finding)

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
        org.nb_occurences += 1
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


def gen_finding_hash(finding: Finding) -> str:
    """Generate a hash for a finding that is used for deduplication of findings inside the current report"""
    endpoint = finding.unsaved_endpoints[0]
    hash_data = [
        str(endpoint),
        finding.title,
        finding.vuln_id_from_tool,
        finding.severity,
    ]
    return hashlib.sha256("|".join(hash_data).encode("utf-8")).hexdigest()
