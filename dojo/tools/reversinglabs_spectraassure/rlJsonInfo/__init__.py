import copy
import datetime
import json
import logging
import sys
from typing import Any

from .cve_info_node import CveInfoNode

logger = logging.getLogger(__name__)  # noqa: RUF067

"""
# rl-json report

Note:
This is all ReversingLabs terminology.
DefectDojo also has `components`,
but that reflects to purl's of rl:components or rl:dependencies depending on where the cve was detected.

A description of  the `rl.json report` but cut up in usable parts.
See also [rl-json-schema](https://docs.secure.software/cli/rl-json-schema) .

## Metadata

The Main metadata components in the rl-json-report metadata file are: (2025-06).

- assessments <br>
A summary of key risks or safety concerns found in your software.
Detected risks are grouped into categories according to their shared characteristics.
Every policy is mapped to a risk category.
When that policy is violated, an issue is reported to cause risk in that category.

- components <br>
Components detected and processed in the analyzed software, represented as a map of unique component IDs.
For every component-id,
  the same information is listed as for the whole software package in the report.info.file object.

- cryptography <br>
Cryptographic assets detected in the analyzed software.

- dependencies <br>
Dependencies detected and processed in the analyzed software,
  represented as a map of dependency IDs.
For every dependency-id,
  the same information is listed as for the whole software package in the report.info.file.identity object.

- indicators <br>
Behavior indicators for the analyzed software as identified by the Spectra Assure engine.

- licenses <br>
A list of licenses found in the analyzed software package.

- ml_models <br>
Machine learning model card with information about the ML models detected in the analyzed software package.

- secrets <br>
Sensitive information (secrets) detected in the analyzed software package.

- services <br>
Networking services detected in the analyzed software package.
In the context of Spectra Assure reports, services are network locations that the analyzed software reaches out to.

- violations <br>
Policy violations detected in the analyzed software package.

- vulnerabilities <br>
Known vulnerabilities affecting analyzed software components and dependencies.
CVE nomenclature is preferred,
  but alternatives may be used if the CVE number is not available for the detected vulnerability.

## Chains
Data is chained so that items point to relevant other items like:

    digraph "rl-json-report-components" {
        rankdir=LR

        // the toplevel entrypoint
        report

        // first level sub keys
        info
        metadata

        // info sub items
        detections
        disabled
        file
        inhibitors
        properties
        statistics
        unpacking
        warnings

        // metadata sub items
        assessments
        components
        cryptography
        dependencies
        indicators
        licenses
        secrets
        services
        violations
        vulnerabilities
        algorithms
        certificates
        materials

        // EDGES
        edge [color=black]
        report -> info
        report -> metadata

        edge [color=blue]
        info -> detections
        info -> disabled
        info -> file
        info -> statistics -> quality
        info -> properties
        info -> inhibitors
        info -> unpacking
        info -> warnings

        edge [color=red]
        metadata -> assessments
        metadata -> components
        metadata -> cryptography
        metadata -> dependencies
        metadata -> indicators
        metadata -> licenses
        metadata -> secrets
        metadata -> services
        metadata -> violations
        metadata -> vulnerabilities

        edge [color=brown]
        cryptography -> algorithms
        cryptography -> certificates
        cryptography -> materials

        edge [color=green,style=dotted]
        algorithms -> components
        certificates -> components
        materials -> components
        secrets -> components
        services -> components
        violations -> components
        dependencies -> vulnerabilities
        licenses -> violations
        components -> dependencies
        vulnerabilities -> violations
    }

## Extracting Findings

Components are extracted files embedded in the main file that was provided to the scanner.
For example zip archives, iso images, docker images, windows installers, rpm's and so forth
are all files that when scanned produce a collection of components (embedded files in the main file scanned).

The current focus for extracting findings is vulnerabilities (cve's) on items,
where items can be:

1. `component` -> `vulnerability` <br>
In  the case of components without dependencies the vulnerability is detected directly on the extracted component file.
2. `component` -> `depdendency` -> `vulnerability` <br>
In the case where a vulnerability is detected on a dependency,
we need the full chain in order to preserve the full path of detection.

"""


class RlJsonInfo:  # noqa: RUF067

    SCAN_TOOL_NAME: str = "ReversingLabs SpectraAssure"

    info: dict[str, Any]

    # we currently only use components, dependencies and vulnerabilities
    known_metadata_sub_keys: list[str] = [
        "assessments",
        "components",  # we use this
        "cryptography",
        "dependencies",  # we use this
        "indicators",
        "licenses",
        "ml_models",
        "services",
        "secrets",
        "violations",
        "vulnerabilities",  # we use this
    ]

    assessments: dict[str, Any]
    components: dict[str, Any]
    cryptography: dict[str, Any]
    dependencies: dict[str, Any]
    indicators: dict[str, Any]
    licenses: dict[str, Any]
    ml_models: dict[str, Any]
    services: dict[str, Any]
    secrets: dict[str, Any]
    violations: dict[str, Any]
    vulnerabilities: dict[str, Any]

    _rest: dict[str, Any]  # after extracting and removing known sub key data, what remains goes here

    sverity_map: dict[int, str] = {
        1: "Info",
        2: "Low",
        3: "Medium",
        4: "High",
        5: "Critical",
    }

    common_tags_map: dict[str, str] = {
        "FIXABLE": "Fix Available",
        "EXISTS": "Exploit Exists",
        "MALWARE": "Exploited by Malware",
        "MANDATE": "Patching Mandated",
        "UNPROVEN": "CVE Discovered",
    }

    # sort order, to align with Spectra Assure Portal
    # 1: Fix Available
    # 2: Exploit exists
    # 3: Exploited my malware
    # 4: Patch mandated

    impact_sort_order: list[str] = [
        "Fix Available",
        "Exploit Exists",
        "Exploited by Malware",
        "Patching Mandated",
        "CVE Discovered",
    ]

    # dict:cve, comp_uuid, dep_uuid | None -> CveInfoNode
    # for cve on components we get the info with path: cve.comp_uuid.None
    # for cve on dependency on component we het the info with path: cve.dep_uuid.comp_uuid
    _results: dict[str, dict[str, dict[str | None, CveInfoNode]]]

    def __init__(
        self,
        file_handle: Any,
    ) -> None:
        self.file_name: str = file_handle.name
        logger.debug("file: %s", self.file_name)

        self.data: dict[str, Any] = json.load(file_handle)
        self._results = {}
        self._get_info()
        self._get_meta()
        self._get_rest()

    def _get_info(
        self,
    ) -> None:
        logger.debug("")
        report = self.data.get("report", {})
        key = "info"
        if key in report:
            self.info = copy.deepcopy(report.get(key, {}))
            del report[key]

    def _get_meta(
        self,
    ) -> None:
        logger.debug("")
        report = self.data.get("report", {})
        metadata = report.get("metadata", {})

        # make all the known meta sub keys into instance dicts
        for name in self.known_metadata_sub_keys:
            if name in metadata:
                setattr(
                    self,
                    name,
                    copy.deepcopy(metadata.get(name, {})),
                )
                del metadata[name]

        if len(metadata) == 0:
            del report["metadata"]

        if len(report) == 0:
            del self.data["report"]

    def _get_rest(
        self,
    ) -> None:
        logger.debug("")

        self._rest = copy.deepcopy(self.data)
        self.data = {}

    def _find_sha256_in_components(
        self,
        sha256: str,
    ) -> bool:
        logger.debug("")

        for component in self.components.values():
            comp_sha256 = self._get_sha256(data=component)
            if comp_sha256 == sha256:
                return True

        return False

    def _add_to_results(
        self,
        cve: str,
        comp_uuid: str,
        dep_uuid: str | None,
        cve_info_node_instance: CveInfoNode | None,
    ) -> None:
        logger.debug("")

        if cve_info_node_instance is None:
            return

        # prep empty keys
        if cve not in self._results:
            self._results[cve] = {}
        if comp_uuid not in self._results[cve]:
            self._results[cve][comp_uuid] = {}

        # put the data in
        if dep_uuid not in self._results[cve][comp_uuid]:
            self._results[cve][comp_uuid][dep_uuid] = cve_info_node_instance

    def _get_sha256(
        self,
        data: dict[str, Any],
    ) -> str:
        logger.debug("")
        # all components are derived from unpacked files and so have a hash set
        # we need the sha256
        key = "sha256"
        h = data.get("hashes", [])
        for item in h:
            if item[0] == key:
                return str(item[1])

        logger.error("no '%s' found for this item %s", key, data)
        return ""

    def _score_to_severity(
        self,
        score: float,
    ) -> str:
        logger.debug("")

        if score >= 9:
            return self.sverity_map[5]

        if score >= 7:
            return self.sverity_map[4]

        if score >= 4:
            return self.sverity_map[3]

        if score > 0:
            return self.sverity_map[2]

        return self.sverity_map[1]

    def _use_path_or_name(
        self,
        *,
        data: dict[str, Any],
        purl: str,
        name_first: bool = False,
        prefer_path: bool = True,
    ) -> str:
        logger.debug("")
        # path or name may be empty so look for the non empty one
        # with name_first we first look at the name
        # with prefer path we use path if it is not empty
        # if we have a valid purl
        #   prefer to derive the name from the purl

        path = data.get("path", "")
        name = data.get("name", "")

        if name_first and len(name) > 0:
            return str(name)

        if prefer_path and len(path) > 0:
            return str(path)

        if purl and len(purl) > 0 and "@" in purl:
            s = purl
            if "/" in s:
                ii = purl.index("/")
                s = purl[ii + 1 :]
            aa = s.split("@")
            name = aa[0]
            # version = aa[1]
            return str(name)

        fallback = ""

        if name_first is False:
            if path:
                return str(path)
            if name:
                return str(name)

            return fallback

        if name:
            return str(name)

        if path:
            return str(path)

        return fallback

    def _get_tags_from_cve(self, this_cve: dict[str, Any]) -> list[str]:
        tags: list[str] = []
        exploit = this_cve.get("exploit", [])
        if len(exploit) == 0:
            return tags  # we have no exploit info so no tags

        # turn cve exploit info into tags
        for key in exploit:
            tag = self.common_tags_map.get(key)
            if tag is None:
                logger.warning("missing tag for key: %s", key)
                continue
            tags.append(tag)

        return tags

    def _make_impact_from_tags(
        self,
        tags: list[str],
        impact: str | None,
    ) -> str:
        if impact is None:
            impact = ""

        for tag in self.impact_sort_order:
            if tag in tags:
                impact += tag + "\n"

        return impact

    def _make_new_cve_info_node(
        self,
        cve: str,
        comp_uuid: str,
        dep_uuid: str | None,
        active: Any,
    ) -> CveInfoNode | None:
        """Collect all info we can extract from the cve and put in in the CveInfoNode"""
        logger.debug("")

        this_cve = self.vulnerabilities.get(cve)
        if this_cve is None:
            logger.error("missing cve info for: %s", cve)
            return None

        cve_info_node_instance = CveInfoNode()
        cve_info_node_instance.cve = cve
        cve_info_node_instance.comp_uuid = comp_uuid
        cve_info_node_instance.dep_uuid = dep_uuid
        cve_info_node_instance.active = bool(active)

        f_info: dict[str, Any] = self.info.get("file", {})
        cve_info_node_instance.original_file = str(f_info.get("name", ""))
        cve_info_node_instance.original_file_sha256 = self._get_sha256(f_info)

        cve_info_node_instance.scan_date = datetime.datetime.fromisoformat(self._rest["timestamp"]).date()
        cve_info_node_instance.scan_tool = self.SCAN_TOOL_NAME
        cve_info_node_instance.scan_tool_version = self._rest.get("version", "no_scan_tool_version_specified")

        cve_info_node_instance.cvss_version = int(this_cve.get("cvss", {}).get("version", "0"))

        score = float(this_cve.get("cvss", {}).get("baseScore", "0.0"))
        cve_info_node_instance.score = score
        cve_info_node_instance.score_severity = self._score_to_severity(score=score)

        cve_info_node_instance.tags = self._get_tags_from_cve(this_cve)
        cve_info_node_instance.impact = self._make_impact_from_tags(
            cve_info_node_instance.tags,
            cve_info_node_instance.impact,
        )

        return cve_info_node_instance

    def _get_component_purl(
        self,
        component: dict[str, Any],
    ) -> str:
        return str(component.get("identity", {}).get("purl", ""))

    def _get_dependency_purl(
        self,
        dependency: dict[str, Any],
    ) -> str:
        return str(dependency.get("purl", ""))

    def _do_one_cve_component_without_dependencies(
        self,
        comp_uuid: str,
        component: dict[str, Any],
        cve: str,
        active: Any,
    ) -> CveInfoNode | None:
        # one: component -> cve
        # the cve part (now we have one component and one vulnerability)

        logger.debug("comp: %s; cve: %s", comp_uuid, cve)

        cve_info_node_instance = self._make_new_cve_info_node(
            cve=cve,
            active=active,
            comp_uuid=comp_uuid,
            dep_uuid=None,
        )
        if cve_info_node_instance is None:
            return None

        ident = component.get("identity", {})

        c_purl = self._get_component_purl(component=component)

        cve_info_node_instance.component_file_path = self._use_path_or_name(data=component, purl=c_purl)
        cve_info_node_instance.component_file_sha256 = self._get_sha256(data=component)
        cve_info_node_instance.component_file_purl = c_purl
        cve_info_node_instance.component_file_version = ident.get("version", "")
        cve_info_node_instance.component_file_name = component.get("name", "")
        cve_info_node_instance.component_type = "component"
        cve_info_node_instance.component_name = self._use_path_or_name(data=component, purl=c_purl, name_first=True)
        cve_info_node_instance.component_version = ident.get("version", "")
        cve_info_node_instance.component_purl = c_purl
        cve_info_node_instance.make_title_cin(cve=cve)
        cve_info_node_instance.make_description_cin(cve=cve, purl=c_purl)
        cve_info_node_instance.vuln_id_from_tool = cve

        logger.debug("%s", cve_info_node_instance)

        return cve_info_node_instance

    def _get_all_active_cve_on_components_without_dependencies(
        self,
    ) -> None:
        # all: component -> cve
        # the component part, could have many vulnerabilities
        logger.debug("")

        for comp_uuid, component in self.components.items():
            v = component.get("identity", {}).get("vulnerabilities", None)
            if v is None:
                logger.info("no vulnerabilities for component: %s", comp_uuid)
                continue

            for cve in v.get("active", []):
                cve_info_node_instance = self._do_one_cve_component_without_dependencies(
                    comp_uuid=comp_uuid,
                    component=component,
                    cve=cve,
                    active=True,
                )
                self._add_to_results(
                    cve=cve,
                    comp_uuid=comp_uuid,
                    dep_uuid=None,
                    cve_info_node_instance=cve_info_node_instance,
                )

    # =========================================================
    # component -> dependency -> cve
    def _do_one_cve_component_dependency(
        self,
        comp_uuid: str,
        component: dict[str, Any],
        dep_uuid: str,
        dependency: dict[str, Any],
        cve: str,
        active: Any,
    ) -> CveInfoNode | None:
        # one: component -> dependency -> cve
        # the cve part (now we have one component, one dependency, one vulnerability)
        logger.debug("comp: %s; dep: %s; cve: %s", comp_uuid, dep_uuid, cve)

        cve_info_node_instance = self._make_new_cve_info_node(
            cve=cve,
            active=active,
            comp_uuid=comp_uuid,
            dep_uuid=dep_uuid,
        )
        if cve_info_node_instance is None:
            return None

        ident = component.get("identity", {})
        c_purl = self._get_component_purl(component=component)

        cve_info_node_instance.component_file_path = self._use_path_or_name(data=component, purl=c_purl)
        cve_info_node_instance.component_file_sha256 = self._get_sha256(data=component)
        cve_info_node_instance.component_file_purl = c_purl
        cve_info_node_instance.component_file_version = ident.get("version", "")
        cve_info_node_instance.component_file_name = component.get("name", "")
        cve_info_node_instance.component_type = "dependency"
        cve_info_node_instance.component_name = dependency.get(
            "product",
            f"no_{cve_info_node_instance.component_type}_product_provided",
        )
        cve_info_node_instance.component_version = dependency.get(
            "version",
            f"no_{cve_info_node_instance.component_type}_version_provided",
        )
        d_purl = self._get_dependency_purl(dependency=dependency)
        cve_info_node_instance.component_purl = d_purl
        cve_info_node_instance.make_title_cin(cve=cve)
        cve_info_node_instance.make_description_cin(cve=cve, purl=d_purl)
        cve_info_node_instance.vuln_id_from_tool = cve

        dep_purl = dependency.get("purl", "")
        dep_name = dependency.get("product", "")
        dep_version = dependency.get("version", "")

        # if we have a dependency purl then purl, otherwise component product + version
        tail = dep_purl
        if len(tail) == 0:
            tail = f"{dep_name}@{dep_version}"

        logger.debug("%s", cve_info_node_instance)
        return cve_info_node_instance

    def _get_one_active_cve_component_dependency(
        self,
        comp_uuid: str,
        component: dict[str, Any],
        dep_uuid: str,
    ) -> None:
        # one: component -> dependency -> cve
        # the dependency (could have many vulnerabilties)
        logger.debug("")

        dependency = self.dependencies.get(dep_uuid)
        if dependency is None:
            logger.error("missing dependency: %s", dep_uuid)
            return

        # -------------------------------
        v = dependency.get("vulnerabilities")
        if v is None:
            logger.info("no vulnerabilities for dependency: %s", dep_uuid)
            return

        # -------------------------------
        for cve in v.get("active"):
            cve_info_node_instance = self._do_one_cve_component_dependency(
                comp_uuid=comp_uuid,
                component=component,
                dep_uuid=dep_uuid,
                dependency=dependency,
                cve=cve,
                active=True,
            )
            self._add_to_results(
                cve=cve,
                comp_uuid=comp_uuid,
                dep_uuid=dep_uuid,
                cve_info_node_instance=cve_info_node_instance,
            )

    def _get_all_active_cve_on_components_with_dependencies(
        self,
    ) -> None:
        # all: component -> dependency -> cve
        # the component part
        logger.debug("")

        for comp_uuid, component in self.components.items():
            d = component.get("identity", {}).get("dependencies", None)
            if d is None:
                logger.info("no dependencies for component: %s", comp_uuid)
                continue

            for dep_uuid in d:
                # returns one dep_uuid, multiple cve (if any cve)
                self._get_one_active_cve_component_dependency(
                    comp_uuid=comp_uuid,
                    component=component,
                    dep_uuid=dep_uuid,
                )

    def _verify_file_is_also_component(
        self,
    ) -> bool:
        logger.debug("")
        # this is normally always true, but we verify it anyway.
        # the file mentioned in the info part of the report must also be a component.

        file_is_component: bool = False

        f_info: dict[str, Any] = self.info.get("file", {})
        file_sha256 = self._get_sha256(f_info)

        file_is_component = self._find_sha256_in_components(file_sha256)
        if file_is_component is False:
            logger.error("file cannot be found as component: %s", f_info)

        return file_is_component

    # ==== PUBLIC ======
    def get_results_list(self) -> list[CveInfoNode]:
        # self.results[cve][comp_uuid][dep_uuid] -> cve_info_node_instance
        cve_info_node_list: list[CveInfoNode] = []
        for components in self._results.values():
            for component in components.values():
                for cve_info_node_instance in component.values():
                    cve_info_node_list.append(cve_info_node_instance)
        return cve_info_node_list

    def print_results_to_file_or_stdout(
        self,
        file_handle: Any = sys.stdout,
    ) -> None:
        def default(o: Any) -> Any:
            if type(o) is CveInfoNode:
                return o.__dict__

            if type(o) is datetime.date:
                return o.isoformat()  # YYYY-MM-DD

            if type(o) is datetime.datetime:
                return o.isoformat()  # YYYY-MM-DD T hh:mm:ss <tz info>

            msg: str = f"unsupported type: {type(o)}"
            raise Exception(msg)

        results: list[Any] = self.get_results_list()

        print(
            json.dumps(
                results,
                indent=4,
                sort_keys=True,
                default=default,
            ),
            file=file_handle,
        )

    def get_cve_active_all(self) -> None:
        """
        0: verify that the info -> file sha256 comes back as a component,
           so we can forget about it as it will be processed as a component
        A: walk over components with active vulnerabilities
        B: walk over components -> dependencies with active vulnerabilities
        """
        logger.debug("")

        self.file_is_component = self._verify_file_is_also_component()
        self._get_all_active_cve_on_components_without_dependencies()
        self._get_all_active_cve_on_components_with_dependencies()
