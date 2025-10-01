# noqa: RUF100
import hashlib
import logging
from typing import Any

from dojo.models import Finding
from dojo.tools.reversinglabs_spectraassure.rlJsonInfo import RlJsonInfo
from dojo.tools.reversinglabs_spectraassure.rlJsonInfo.cve_info_node import CveInfoNode

logger = logging.getLogger(__name__)

SCAN_TYPE = "ReversingLabs Spectra Assure"

"""
The actual parsing is done by `RlJsonInfo` and it stores data as a collection of `CveInfoNode`
A `CveInfoNode` matches a dd.Finding more closely and makes the collection of Findings easy.

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
            file_path=node.component_file_path,
            component_name=node.component_name,
            component_version=node.component_version,
            nb_occurences=1,
            hash_code=key,  # sha256 on title
            references=None,  # future: urls
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
        return [SCAN_TYPE]

    def get_label_for_scan_types(self, scan_type: str) -> str:
        return scan_type

    def get_description_for_scan_types(self, scan_type: str) -> str:
        if scan_type == SCAN_TYPE:
            return "Import the SpectraAssure report.rl.json file."
        return f"Unknown Scan Type; {scan_type}"

    def get_findings(
        self,
        file: Any,
        test: Any,
    ) -> list[Finding]:
        # ------------------------------------
        rl_json_info_instance = RlJsonInfo(file_handle=file)
        rl_json_info_instance.get_cve_active_all()

        self._findings: list[Finding] = []
        self._duplicates: dict[str, Finding] = {}

        for cve_info_node_instance in rl_json_info_instance.get_results_list():
            finding = self._one_finding(
                node=cve_info_node_instance,
                test=test,
            )
            if finding is None:
                continue

            key = finding.hash_code
            if key not in self._duplicates:
                self._findings.append(finding)
                self._duplicates[key] = finding
                continue

            dup = self._duplicates[key]
            if dup:
                dup.description += finding.description
                dup.nb_occurences += 1

        # ------------------------------------
        return self._findings
