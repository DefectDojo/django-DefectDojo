from typing import NamedTuple


class BlackduckBinaryAnalysisFinding(NamedTuple):
    report_name: str
    component: str
    version: str
    latest_version: str
    cve: str
    matching_type: str
    cvss_v2: str
    cve_publication_date: str
    object_compilation_date: str
    object_name: str
    object_full_path: str
    object_sha1: str
    cvss_v3: str
    cvss_vector_v2: str
    cvss_vector_v3: str
    summary: str
    distribution_package: str
    cvss_distribution_v2: str
    cvss_distribution_v3: str
    triage_vectors: str
    unresolving_triage_vectors: str
    note_type: str
    note_reason: str
    vulnerability_url: str
    missing_exploit_mitigations: str
    bdsa: str
    version_override_type: str
