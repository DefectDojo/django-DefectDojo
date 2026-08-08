"""Parse Xygeni SCA (dependency-vulnerability) reports into DefectDojo Findings."""

from dojo.models import Finding
from dojo.tools.xygeni._common import map_severity, parse_cwes


def parse_sca(data, test):
    """
    Convert a Xygeni SCA JSON report into a list of Findings.

    The Xygeni SCA report stores findings nested inside ``dependencies[]`` —
    each dependency may carry a ``vulnerabilities[]`` array of CVE/GHSA
    advisories. This parser emits one Finding per nested vulnerability.
    """
    findings = []
    for dep in data.get("dependencies") or []:
        findings.extend(
            _build_finding(dep, vuln, test) for vuln in dep.get("vulnerabilities") or []
        )
    return findings


def _build_finding(dep, vuln, test):
    component_name = dep.get("name")
    component_version = dep.get("version")

    title = str(vuln.get("cve") or vuln.get("id") or "Xygeni SCA finding")

    fixed_version = vuln.get("fixedVersion")
    mitigation = None
    if fixed_version and component_name:
        mitigation = f"Upgrade {component_name} to version {fixed_version} or later."
    elif fixed_version:
        mitigation = f"Upgrade to version {fixed_version} or later."

    references = "\n".join(str(r) for r in (vuln.get("references") or []) if r) or None

    cvss_score = vuln.get("overallCvssScore")
    if cvss_score is None or cvss_score < 0:
        cvss_score = None

    primary_cwe, all_cwes = parse_cwes(cwes=vuln.get("cwes"))

    finding = Finding(
        test=test,
        title=title,
        description=str(vuln.get("description") or ""),
        severity=map_severity(vuln.get("severity")),
        cwe=primary_cwe,
        cvssv3_score=cvss_score,
        mitigation=mitigation,
        references=references,
        component_name=component_name,
        component_version=component_version,
        static_finding=True,
        dynamic_finding=False,
        # ``uniqueHash`` (``CVE#component:version``) is Xygeni's identity for the finding across
        # scans. ``userId`` is the user-friendly vulnerability id (CVE / GHSA / OSV), used as the
        # non-unique grouping id.
        unique_id_from_tool=vuln.get("uniqueHash"),
        vuln_id_from_tool=vuln.get("userId"),
    )

    if vuln.get("cve"):
        finding.cve = vuln["cve"]

    if all_cwes:
        finding.unsaved_cwes = all_cwes

    finding.unsaved_vulnerability_ids = _collect_vulnerability_ids(vuln)
    return finding


def _collect_vulnerability_ids(vuln):
    """Return a deduplicated list of CVE/GHSA-style aliases for a Xygeni SCA vulnerability."""
    ids = []
    seen = set()
    for value in (vuln.get("cve"), *(vuln.get("aliases") or [])):
        if not value:
            continue
        token = str(value)
        if token not in seen:
            seen.add(token)
            ids.append(token)
    return ids
