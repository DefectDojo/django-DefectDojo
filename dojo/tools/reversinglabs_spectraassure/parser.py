# noqa: RUF100
import logging
from typing import Any

from dojo.location.feature import locations_enabled
from dojo.models import Finding
from dojo.tools.locations import LocationData
from dojo.tools.reversinglabs_spectraassure.rl_json_info import RlJsonInfo
from dojo.tools.reversinglabs_spectraassure.rl_json_info.cve_info_node import CveInfoNode

logger = logging.getLogger(__name__)

SCAN_TYPE = "ReversingLabs Spectra Assure"

"""
The actual parsing is done by `RlJsonInfo` and it stores data as a collection of `CveInfoNode`
A `CveInfoNode` matches a dd.Finding more closely and makes the collection of Findings easy.
"""


class ReversinglabsSpectraassureParser:
    # --------------------------------------------
    # This class MUST have an empty constructor or no constructor

    @staticmethod
    def _unique_id(node: CveInfoNode) -> str:
        # What was found, in which exact component file. A different sha256 is a different binary even
        # under the same name and path (HxD ships one per language), so it must be a different finding.
        # Without a sha256, fall back to the component path.
        where = (
            f"sha256:{node.component_file_sha256}" if node.component_file_sha256 else f"path:{node.component_file_path}"
        )
        return f"{node.vuln_id_from_tool}/{where}"

    def _one_finding(
        self,
        *,
        node: CveInfoNode,
        test: Any,
    ) -> Finding:
        logger.debug("_one_finding: %s", node)

        cvssv3_score = None
        if node.cvss_version == 3:
            cvssv3_score = node.score or None

        cvssv4_score = None
        if node.cvss_version == 4:
            cvssv4_score = node.score or None

        description = f"# {node.title}\n\n{node.description}"  # CommonMark needs the space after '#'

        finding = Finding(
            date=node.scan_date,
            title=node.title,
            description=description,
            cve=node.cve,
            cvssv3_score=cvssv3_score,
            cvssv4_score=cvssv4_score,
            severity=node.score_severity,
            vuln_id_from_tool=node.vuln_id_from_tool,
            file_path=node.component_file_path,
            # empty -> None: DefectDojo hashes the unsaved finding (import and reimport) but stores blank component
            # fields as NULL, so an empty string would hash differently from any later recompute ('' vs 'None')
            component_name=node.component_name or None,
            component_version=node.component_version or None,
            nb_occurences=1,
            unique_id_from_tool=self._unique_id(node),
            references=None,  # future: urls
            active=True,  # this is the DefectDojo active field, nothing to do with node.active field
            test=test,
            static_finding=True,
            dynamic_finding=False,
            known_exploited=node.known_exploited,
        )

        finding.unsaved_vulnerability_ids = [node.cve] if node.cve else []
        finding.unsaved_tags = node.tags
        finding.impact = node.impact

        # Locations (V3_FEATURE_LOCATIONS): attach the vulnerable package as a dependency location.
        # component_purl is the dependency's purl for dependency findings and the component's own
        # purl otherwise; policy violation findings have none and get no location.
        # Check locations_enabled() first: with the feature off, Finding has no unsaved_locations.
        if locations_enabled() and node.component_purl:
            finding.unsaved_locations.append(
                LocationData.dependency(purl=node.component_purl, file_path=node.component_file_path),
            )

        return finding

    # --------------------------------------------
    # PUBLIC
    def get_scan_types(self) -> list[str]:
        logger.debug("get_scan_types")
        return [SCAN_TYPE]

    def get_label_for_scan_types(self, scan_type: str) -> str:
        logger.debug("get_label_for_scan_types")
        return scan_type

    def get_description_for_scan_types(self, scan_type: str) -> str:
        logger.debug("get_description_for_scan_types")

        if scan_type == SCAN_TYPE:
            return "Import the SpectraAssure report.rl.json file."
        return f"Unknown Scan Type; {scan_type}"

    def get_findings(
        self,
        file: Any,
        test: Any,
    ) -> list[Finding]:
        logger.debug("get_findings")

        self._findings: list[Finding] = []
        self._duplicates: dict[tuple[str, str, str], Finding] = {}

        try:
            info = RlJsonInfo(file_handle=file)
            info.build_findings()
            nodes = list(info.get_results_list())
        except (ValueError, KeyError, TypeError) as e:
            msg = f"Not a valid Spectra Assure rl.json report: {e}"
            raise ValueError(msg) from e

        for node in nodes:
            finding = self._one_finding(
                node=node,
                test=test,
            )

            # The identity DefectDojo hashes (HASHCODE_FIELDS_PER_SCANNER). Within one report a repeat is the
            # same component file showing the same issue again, e.g. one binary at two paths: count it and note
            # where, instead of appending the whole description again.
            # built from the node (str), not read back from the Finding, where these fields are Optional
            key = (self._unique_id(node), node.component_name, node.component_version)
            dup = self._duplicates.get(key)
            if dup is None:
                self._findings.append(finding)
                self._duplicates[key] = finding
                continue

            dup.nb_occurences += 1
            also = f"- also at: {finding.file_path}"
            if finding.file_path != dup.file_path and also not in dup.description:
                dup.description = f"{dup.description.rstrip()}\n{also}\n"

        return self._findings
