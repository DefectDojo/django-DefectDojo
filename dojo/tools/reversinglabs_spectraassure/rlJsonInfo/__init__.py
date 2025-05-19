from typing import (
    Dict,
    List,
    Any,
    Iterator,
)
import sys
import os
import datetime
import logging
import copy
import gc
import json

from .cve_info_node import CveInfoNode

logger = logging.getLogger(__name__)


class RlJsonInfo:
    """
    The info of the rl.json reports but cut up in usable parts
    """

    SCAN_TOOL_NAME: str = "ReversingLabs SpectraAssure"

    info: Dict[str, Any]
    #
    assessments: Dict[str, Any]
    components: Dict[str, Any]
    cryptography: Dict[str, Any]
    dependencies: Dict[str, Any]
    indicators: Dict[str, Any]
    licenses: Dict[str, Any]
    ml_models: Dict[str, Any]
    services: Dict[str, Any]
    secrets: Dict[str, Any]
    violations: Dict[str, Any]
    vulnerabilities: Dict[str, Any]
    #
    _rest: Dict[str, Any]

    _metadata: List[str] = [
        "assessments",
        "components",
        "cryptography",
        "dependencies",
        "indicators",
        "licenses",
        "ml_models",
        "services",
        "secrets",
        "violations",
        "vulnerabilities",
    ]

    sMap: Dict[int, str] = {
        1: "Info",
        2: "Low",
        3: "Medium",
        4: "High",
        5: "Critical",
    }

    tags: Dict[str, str] = {
        "FIXABLE": "Fix Available",
        "EXISTS": "Exploit Exists",
        "MALWARE": "Exploited by Malware",
        "MANDATE": "Patching Mandated",
        "UNPROVEN": "CVE Discovered",
    }

    # sort order, to align wit Spectra Assure Portal
    # 1: Fix Available
    # 2: Exploit exists
    # 3: Exploited my malware
    # 4: Patch mandated

    impact_sort_order: List[str] = [
        "Fix Available",
        "Exploit Exists",
        "Exploited by Malware",
        "Patching Mandated",
        "CVE Discovered",
    ]

    # cve, comp_uuid, dep_uuid | None -> CveInfoNode
    _results: Dict[str, Dict[str, Dict[str | None, CveInfoNode]]]

    def __init__(
        self,
        file_handle: Any,
    ) -> None:
        self.file_name: str = file_handle.name
        logger.debug("file: %s", self.file_name)

        self.data: Dict[str, Any] = json.load(file_handle)
        self._results = {}

        self.RL_JSON_WITH_CG_COLLECT: bool = False
        if os.getenv("RL_JSON_WITH_CG_COLLECT", False):
            self.RL_JSON_WITH_CG_COLLECT = True

        self._get_info()
        self._get_meta()
        self._get_rest()

        if self.RL_JSON_WITH_CG_COLLECT is True:
            gc.collect()

    def _get_info(
        self,
    ) -> None:
        logger.debug("")
        r = self.data.get("report", {})
        k = "info"
        if k in r:
            self.info = copy.deepcopy(r.get(k, {}))
            del r[k]

    def _get_meta(
        self,
    ) -> None:
        logger.debug("")
        r = self.data.get("report", {})
        m = r.get("metadata", {})

        for name in self._metadata:
            if name in m:
                setattr(
                    self,
                    name,
                    copy.deepcopy(m.get(name, {})),
                )
                del m[name]

        if len(m) == 0:
            del r["metadata"]

        if len(r) == 0:
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

        for comp_uuid, component in self.components.items():
            comp_sha256 = self._get_sha256(data=component)
            if comp_sha256 == sha256:
                return True

        return False

    def _add_to_results(
        self,
        cve: str,
        comp_uuid: str,
        dep_uuid: str | None,
        cin: CveInfoNode | None,
    ) -> None:
        logger.debug("")

        if cin is None:
            return

        rr = self._results
        if cve not in rr:
            rr[cve] = {}

        if comp_uuid not in rr[cve]:
            rr[cve][comp_uuid] = {}

        assert dep_uuid not in rr[cve][comp_uuid]
        rr[cve][comp_uuid][dep_uuid] = cin

    def _get_sha256(
        self,
        data: Dict[str, Any],
    ) -> str:
        logger.debug("")
        k = "sha256"

        h = data.get("hashes", [])
        for item in h:
            if item[0] == k:
                return str(item[1])

        logger.error("no '%s' found for this item %s", k, data)

        return ""

    def _verify_file_is_also_component(
        self,
    ) -> bool:
        logger.debug("")

        rr: bool = False

        f_info: Dict[str, Any] = self.info.get("file", {})
        file_sha256 = self._get_sha256(f_info)

        rr = self._find_sha256_in_components(file_sha256)
        if rr is False:
            logger.error("file cannot be found as component: %s", f_info)

        return rr

    def _score_to_severity(
        self,
        score: float,
    ) -> str:
        logger.debug("")

        if score >= 9:
            return self.sMap[5]

        if score >= 7:
            return self.sMap[4]

        if score >= 4:
            return self.sMap[3]

        if score > 0:
            return self.sMap[2]

        return self.sMap[1]

    def _use_path_or_name(
        self,
        *,
        data: Dict[str, Any],
        purl: str,
        name_first: bool = False,
        prefer_path: bool = True,
    ) -> str:
        logger.debug("")

        path = data.get("path", "")
        name = data.get("name", "")

        if name_first and len(name) > 0:
            return str(name)

        if prefer_path and len(path) > 0:
            return str(path)

        # if we have a valid purl
        #   prefer to derive the name from the purl
        if purl and len(purl) > 0 and "@" in purl:
            s = purl
            if "/" in s:
                ii = purl.index("/")
                s = purl[ii + 1 :]
            aa = s.split("@")
            name = aa[0]
            # version = aa[1]
            return str(name)

        k = ""

        if name_first is False:
            if path != "":
                return str(path)
            if name != "":
                return str(name)

            return k

        if name != "":
            return str(name)

        if path != "":
            return str(path)

        return k

    def _get_tags_from_cve(self, this_cve: Dict[str, Any]) -> List[str]:
        tags: List[str] = []
        exploit = this_cve.get("exploit", [])
        if len(exploit) == 0:
            return tags

        for key in exploit:
            tag = self.tags.get(key)
            if tag is None:
                logger.warning("missing tag for key: %s", key)
                continue

            tags.append(tag)

        return tags

    def _make_impact_from_tags(
        self,
        tags: List[str],
        impact: str | None,
    ) -> str:
        if impact is None:
            impact = ""

        for tag in self.impact_sort_order:
            if tag in tags:
                impact += tag + "\n"

        return impact

    def _make_new_cin(
        self,
        cve: str,
        comp_uuid: str,
        dep_uuid: str | None,
        active: bool,
    ) -> CveInfoNode | None:
        """collect all info we can extract from the cve"""
        logger.debug("")

        this_cve = self.vulnerabilities.get(cve)
        if this_cve is None:
            logger.error("missing cve info for: %s", cve)
            return None

        cin = CveInfoNode()
        #
        cin.cve = cve
        cin.comp_uuid = comp_uuid
        cin.dep_uuid = dep_uuid
        cin.active = active
        #
        f_info: Dict[str, Any] = self.info.get("file", {})
        cin.original_file = str(f_info.get("name", ""))
        cin.original_file_sha256 = self._get_sha256(f_info)

        cin.scan_date = datetime.datetime.fromisoformat(self._rest["timestamp"]).date()
        cin.scan_tool = self.SCAN_TOOL_NAME
        cin.scan_tool_version = self._rest.get("version", "no_scan_tool_version_specified")
        cin.cvss_version = int(this_cve.get("cvss", {}).get("version", "0"))
        #
        score = float(this_cve.get("cvss", {}).get("baseScore", "0.0"))
        cin.score = score
        cin.score_severity = self._score_to_severity(score=score)

        # TODO: tags
        cin.tags = self._get_tags_from_cve(this_cve)
        cin.impact = self._make_impact_from_tags(cin.tags, cin.impact)

        return cin

    def _get_component_purl(
        self,
        component: Dict[str, Any],
    ) -> str:
        c_purl = str(component.get("identity", {}).get("purl", ""))
        return c_purl

    def _get_dependency_purl(
        self,
        dependency: Dict[str, Any],
    ) -> str:
        d_purl = str(dependency.get("purl", ""))
        return d_purl

    def _do_one_cve_component_dependency(
        self,
        comp_uuid: str,
        component: Dict[str, Any],
        dep_uuid: str,
        dependency: Dict[str, Any],
        cve: str,
        active: bool,
    ) -> CveInfoNode | None:
        logger.debug("comp: %s; dep: %s; cve: %s", comp_uuid, dep_uuid, cve)

        cin = self._make_new_cin(
            cve=cve,
            active=active,
            comp_uuid=comp_uuid,
            dep_uuid=dep_uuid,
        )
        if cin is None:
            return None

        ident = component.get("identity", {})
        c_purl = self._get_component_purl(component=component)

        cin.component_file_path = self._use_path_or_name(data=component, purl=c_purl)
        cin.component_file_sha256 = self._get_sha256(data=component)
        cin.component_file_purl = c_purl
        cin.component_file_version = ident.get("version", "")
        cin.component_file_name = component.get("name", "")
        #
        cin.component_type = "dependency"
        cin.component_name = dependency.get("product", f"no_{cin.component_type}_product_provided")
        cin.component_version = dependency.get("version", f"no_{cin.component_type}_version_provided")
        #
        d_purl = self._get_dependency_purl(dependency=dependency)
        cin.component_purl = d_purl
        #
        cin.unique_id_from_tool = "dependency: " + dep_uuid
        cin.vuln_id_from_tool = cve
        #
        cin._make_title_cin(cve=cve)
        cin._make_description_cin(cve=cve, purl=d_purl)

        logger.debug("%s", cin)

        return cin

    def _do_one_cve_component_without_dependencies(
        self,
        comp_uuid: str,
        component: Dict[str, Any],
        cve: str,
        active: bool,
    ) -> CveInfoNode | None:
        logger.debug("comp: %s; cve: %s", comp_uuid, cve)

        cin = self._make_new_cin(cve=cve, active=active, comp_uuid=comp_uuid, dep_uuid=None)
        if cin is None:
            return None

        ident = component.get("identity", {})

        c_purl = self._get_component_purl(component=component)
        #
        cin.component_file_path = self._use_path_or_name(data=component, purl=c_purl)
        cin.component_file_sha256 = self._get_sha256(data=component)
        cin.component_file_purl = c_purl
        cin.component_file_version = ident.get("version", "")
        cin.component_file_name = component.get("name", "")
        #
        cin.component_type = "component"
        cin.component_name = self._use_path_or_name(data=component, purl=c_purl, name_first=True)
        cin.component_version = ident.get("version", "")
        cin.component_purl = c_purl
        #
        cin.unique_id_from_tool = "component: " + comp_uuid
        cin.vuln_id_from_tool = cve
        cin.active = active

        cin._make_title_cin(cve=cve)
        cin._make_description_cin(cve=cve, purl=c_purl)

        logger.debug("%s", cin)

        return cin

    def _get_one_active_cve_component_dependency(
        self,
        comp_uuid: str,
        component: Dict[str, Any],
        dep_uuid: str,
    ) -> None:
        logger.debug("")

        dependency = self.dependencies.get(dep_uuid)
        if dependency is None:
            logger.error("missing dependency", dep_uuid)
            return

        # -------------------------------
        v = dependency.get("vulnerabilities")
        if v is None:
            logger.info("no vulnerabilities for dependency: %s", dep_uuid)
            return

        # -------------------------------
        for cve in v.get("active"):
            cin = self._do_one_cve_component_dependency(
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
                cin=cin,
            )

    def _get_all_active_cve_on_components_without_dependencies(
        self,
    ) -> None:
        logger.debug("")

        for comp_uuid, component in self.components.items():
            v = component.get("identity", {}).get("vulnerabilities", None)
            if v is None:
                logger.info("no vulnerabilities for component: %s", comp_uuid)
                continue

            for cve in v.get("active", []):
                cin = self._do_one_cve_component_without_dependencies(
                    comp_uuid=comp_uuid,
                    component=component,
                    cve=cve,
                    active=True,
                )
                self._add_to_results(
                    cve=cve,
                    comp_uuid=comp_uuid,
                    dep_uuid=None,
                    cin=cin,
                )

    def _get_all_active_cve_on_components_with_dependencies(
        self,
    ) -> None:
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

    # ==== PUBLIC ======
    def iter_results(self) -> Iterator[CveInfoNode]:
        for cve, compo in self._results.items():
            for comp_uuid, component in compo.items():
                for dep_uuid, cin in component.items():
                    yield cin

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

            raise Exception(f"unsupported type: {type(o)}")

        rr: List[Any] = []
        for cin in self.iter_results():
            rr.append(cin)
        print(
            json.dumps(
                rr,
                indent=4,
                sort_keys=True,
                default=default,
            ),
            file=file_handle,
        )

    def get_cve_active_all(self) -> None:
        """find get all cve's and add componenet path, sha and version like in `report.cve.csv`

        0:
            verify that the info -> file sha256 comes back as a component

        A:
            walk over components with active vulnerabilities

        B:
            walk over components -> dependencies with active vulnerabilities
        """
        logger.debug("")

        self.file_is_component = self._verify_file_is_also_component()
        self._get_all_active_cve_on_components_without_dependencies()
        self._get_all_active_cve_on_components_with_dependencies()
