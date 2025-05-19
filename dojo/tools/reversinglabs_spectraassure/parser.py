import hashlib
import logging
from typing import Any

from dojo.models import Finding
from dojo.tools.reversinglabs_spectraassure.rlJsonInfo import RlJsonInfo
from dojo.tools.reversinglabs_spectraassure.rlJsonInfo.cve_info_node import CveInfoNode

logger = logging.getLogger(__name__)

WHAT = "ReversingLabs Spectra Assure"

"""
dedup on title:

if a finding is a Dependency:
    title:
        "<cve>, 'dep': <purl | name+version>"

    description:
        "<title>\n<number> component: <purl | name+version>, <sha256>, 'id in report.rl.json': <dep-uuid>\n"

    for each duplicate title: (so the same Dependency):
        increment occurrences and append to description of the first detected:

        "<number+1> component: <purl | name+version>, <sha256>, 'id in report.rl.json': <dep-uuid>\n"

if a finding is a Component it is already unique.
    title:
        "<cve>, 'comp': <purl | name+version>, <sha256>"
        occurrences = 1

    description:
        <title>\n

Note:
    We have components with the same name and version but different hash value.
    This is typical for windows installers with multi language support.
    A good example is: HxDSetup_2.5.0.exe

    Parser for Spectra Assure rl-json files

    This class MUST implement 3 methods:

    - def get_scan_types(self)
        This function return a list of all the scan_type supported by your parser.
        These identifiers are used internally.
        Your parser can support more than one scan_type.
        e.g. some parsers use different identifier to modify the behavior of the parser (aggregate, filter, etc…)

    - def get_label_for_scan_types(self, scan_type)
        This function return a string used to provide some text in the UI (short label)

    - def get_description_for_scan_types(self, scan_type)
        This function return a string used to provide some text in the UI (long description)

    - def get_findings(self, file, test)
        This function return a list of findings

    If your parser has more than 1 scan_type (for detailed mode) you MUST implement:
    - def set_mode(self, mode) method
"""


class ReversinglabsSpectraassureParser:

    # --------------------------------------------
    # This class MUST have an empty constructor or no constructor

    def _find_duplicate(self, key: str) -> Finding | None:
        logger.debug("")

        if key in self._duplicates:
            return self._duplicates

        return None

    def _make_hash(
        self,
        data: str,
    ) -> str:
        # Calculate SHA-256 hash
        d = data.encode()
        return hashlib.sha256(d).hexdigest()

    def _one_finding(
        self,
        *,
        node: CveInfoNode,
        test: Any,
    ) -> Finding:
        logger.debug("%s", node)

        key = self._make_hash(node.title + " " + node.component_file_path)
        cve = node.cve
        finding = Finding(
            date=node.scan_date,
            title=node.title,
            description=node.title + " " + node.description + "\n",
            cve=cve,
            cvssv3_score=node.score,
            severity=node.score_severity,
            vuln_id_from_tool=node.vuln_id_from_tool,
            unique_id_from_tool=node.unique_id_from_tool,  # purl if we have one ?
            file_path=node.component_file_path,
            component_name=node.component_name,
            component_version=node.component_version,
            nb_occurences=1,
            hash_code=key,  # sha256 on title
            references=None,  # future urls
            active=True,  # this is the DefectDojo active field, nothing to do with node.active field
            test=test,
            static_finding=True,
            dynamic_finding=False,
        )
        finding.unsaved_vulnerability_ids = [cve]
        finding.unsaved_tags = node.tags
        finding.impact = node.impact

        return finding

    # --------------------------------------------
    # PUBLIC
    def get_scan_types(self) -> list[str]:
        return [WHAT]

    def get_label_for_scan_types(self, scan_type: str) -> str:
        return scan_type

    def get_description_for_scan_types(self, scan_type: str) -> str:
        if scan_type == WHAT:
            return "Import the SpectraAssure report.rl.json file."
        return f"Unknown Scan Type; {scan_type}"

    def get_findings(
        self,
        file: Any,
        test: Any,
    ) -> list[Finding]:
        # ------------------------------------
        rji = RlJsonInfo(file_handle=file)
        rji.get_cve_active_all()

        self._findings: list[Finding] = []
        self._duplicates: dict[str, Finding] = {}

        for cin in rji.get_results_list():
            finding = self._one_finding(
                node=cin,
                test=test,
            )
            if finding is None:
                continue

            key = finding.hash_code
            if key not in self._duplicates:
                self._findings.append(finding)
                self._duplicates[key] = finding
                continue

            dup = self._duplicates[key]  # but that may be on a different component file, name, version
            if dup:
                dup.description += finding.description
                dup.nb_occurences += 1

        # ------------------------------------
        return self._findings
