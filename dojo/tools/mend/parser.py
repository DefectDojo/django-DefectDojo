import hashlib
import json
import logging

from dojo.models import Finding

__author__ = "dr3dd589"

logger = logging.getLogger(__name__)


class MendParser:
    def get_scan_types(self):
        return ["Mend Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Mend Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON report"

    def get_findings(self, file, test):
        if file is None:
            return []

        data = file.read()
        try:
            content = json.loads(str(data, "utf-8"))
        except Exception:
            content = json.loads(data)

        def _build_common_output(node, lib_name=None):
            # project only available in manual export
            # name --> CVE in manual, library name in pipeline
            cve = None
            component_name = None
            component_version = None
            if "library" in node:
                node.get("project")
                description = (
                    "**Description** : "
                    + node.get("description", "")
                    + "\n\n"
                    + "**Library Name** : "
                    + node["library"].get("name", "")
                    + "\n\n"
                    + "**Library Filename** : "
                    + node["library"].get("filename", "")
                    + "\n\n"
                    + "**Library Description** : "
                    + node["library"].get("description", "")
                    + "\n\n"
                    + "**Library Type** : "
                    + node["library"].get("type", "")
                    + "\n"
                )
                lib_name = node["library"].get("filename")
                component_name = node["library"].get("artifactId")
                component_version = node["library"].get("version")
            else:
                description = node.get("description")

            cve = node.get("name")
            if cve is None:
                title = "CVE-None | " + lib_name
            else:
                title = cve + " | " + lib_name
            # cvss2 by default in CLI, but cvss3 in UI. Adapting to have
            # homogeneous behavior.
            if "cvss3_severity" in node:
                cvss_sev = node.get("cvss3_severity")
            else:
                cvss_sev = node.get("severity")
            severity = cvss_sev.lower().capitalize()

            cvss3_score = node.get("cvss3_score", None)
            cvss3_vector = node.get("scoreMetadataVector", None)
            severity_justification = "CVSS v3 score: {} ({})".format(
                cvss3_score if cvss3_score is not None else "N/A", cvss3_vector if cvss3_vector is not None else "N/A",
            )
            cwe = 1035  # default OWASP a9 until the report actually has them

            mitigation = "N/A"
            if "topFix" in node:
                try:
                    topfix_node = node.get("topFix")
                    mitigation = "**Resolution** ({}): {}\n".format(
                        topfix_node.get("date"),
                        topfix_node.get("fixResolution"),
                    )
                except Exception:
                    logger.exception("Error handling topFix node.")

            filepaths = []
            if "sourceFiles" in node:
                try:
                    sourceFiles_node = node.get("sourceFiles")
                    for sfile in sourceFiles_node:
                        filepaths.append(sfile.get("localPath"))
                except Exception:
                    logger.exception(
                        "Error handling local paths for vulnerability.",
                    )

            new_finding = Finding(
                title=title,
                test=test,
                description=description,
                severity=severity,
                cwe=cwe,
                mitigation=mitigation,
                file_path=", ".join(filepaths),
                component_name=component_name,
                component_version=component_version,
                severity_justification=severity_justification,
                dynamic_finding=True,
                cvssv3=cvss3_vector,
                cvssv3_score=float(cvss3_score) if cvss3_score is not None else None,
            )
            if cve:
                new_finding.unsaved_vulnerability_ids = [cve]

            return new_finding

        findings = []
        if "libraries" in content:
            # we are likely dealing with a report generated from CLI with -generateScanReport,
            # which will output vulnerabilities as an array of a library
            # In this scenario, build up an array
            tree_libs = content.get("libraries")
            for lib_node in tree_libs:
                # get the overall lib info here, before going into vulns
                if (
                    "vulnerabilities" in lib_node
                    and len(lib_node.get("vulnerabilities")) > 0
                ):
                    for vuln in lib_node.get("vulnerabilities"):
                        findings.append(
                            _build_common_output(vuln, lib_node.get("name")),
                        )

        elif "vulnerabilities" in content:
            # likely a manual json export for vulnerabilities only for a project.
            # Vulns are standalone, and library is a property.
            tree_node = content["vulnerabilities"]
            for node in tree_node:
                findings.append(_build_common_output(node))

        def create_finding_key(f: Finding) -> str:
            """Hashes the finding's description and title to retrieve a key for deduplication."""
            return hashlib.md5(
                f.description.encode("utf-8")
                + f.title.encode("utf-8"),
            ).hexdigest()

        dupes = {}
        for finding in findings:
            dupe_key = create_finding_key(finding)
            if dupe_key not in dupes:
                dupes[dupe_key] = finding

        return list(dupes.values())
