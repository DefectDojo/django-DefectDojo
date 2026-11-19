import datetime as dt
import json
import logging
from collections.abc import Iterator
from typing import Any, ClassVar

from packageurl import PackageURL

from .cve_info_node import CveInfoNode, sha256_tag
from .rl_json_secrets import (
    ComponentInfo,
    SecretInfo,
    SecretsExtractor,
    SecretsTree,
    ViolationInfo,
)

logger = logging.getLogger(__name__)


class RlJsonInfo:
    info: dict[str, Any]

    # the metadata subtrees the parser reads; the others (assessments, cryptography,
    # indicators, licenses, ml_models, services) are never looked at
    known_metadata_sub_keys: ClassVar[list[str]] = [
        "components",
        "dependencies",
        "secrets",
        "violations",
        "vulnerabilities",
    ]

    components: dict[str, Any]
    dependencies: dict[str, Any]
    secrets: dict[str, Any]
    violations: dict[str, Any]
    vulnerabilities: dict[str, Any]
    scan_date: dt.date

    severity_map: ClassVar[dict[int, str]] = {
        1: "Info",
        2: "Low",
        3: "Medium",
        4: "High",
        5: "Critical",
    }

    # UNPROVEN ("CVE Discovered" in the Portal) and TRIAGED are deliberately not turned into a tag or an impact line;
    # listed here so they are skipped without the "missing tag" warning an unknown key gets
    ignored_exploit_keys: ClassVar[set[str]] = {"UNPROVEN", "TRIAGED"}

    common_tags_map: ClassVar[dict[str, str]] = {
        "FIXABLE": "Fix Available",
        "EXISTS": "Exploit Exists",
        "MALWARE": "Exploited by Malware",
        "MANDATE": "Patching Mandated",
    }

    # sort order, to align with Spectra Assure Portal
    # 1: Fix Available
    # 2: Exploit exists
    # 3: Exploited by malware
    # 4: Patch mandated

    impact_sort_order: ClassVar[list[str]] = [
        "Fix Available",
        "Exploit Exists",
        "Exploited by Malware",
        "Patching Mandated",  # if present also set known_exploited to True
    ]

    # _results[key][comp_uuid][dep_uuid] -> CveInfoNode
    #   key:      the CVE id for vulnerabilities, <category>-<rule_id> for policy violations
    #   dep_uuid: None for a CVE on the component itself, and for violations
    _results: dict[str | None, dict[str, dict[str | None, CveInfoNode]]]

    def __init__(
        self,
        file_handle: Any,
    ) -> None:
        self.file_name: str = file_handle.name
        logger.debug("file: %s", self.file_name)
        self.info = {}

        self.data: dict[str, Any] = json.load(file_handle)

        self._results = {}
        self._get_info()
        self._get_meta()
        self._get_scan_date()  # after _get_meta(), so a non report file reports the missing 'report' key first
        self.data = {}

    def _get_scan_date(
        self,
    ) -> None:
        logger.debug("_get_scan_date")

        # scan_date has no sensible default: a finding dated 'today' because the report
        # carried no timestamp would be silently wrong, so refuse the file instead.

        k = "timestamp"
        ts = self.data.get(k, None)
        if not ts:
            msg = f"Missing '{k}' key in the json data, this is not a 'report.rl.json' type file"
            raise ValueError(msg)

        try:
            self.scan_date = dt.datetime.fromisoformat(str(ts)).date()
        except ValueError as e:
            msg = f"Invalid '{k}' value in the json data: {ts!r}"
            raise ValueError(msg) from e

    def _get_info(
        self,
    ) -> None:
        logger.debug("_get_info")
        report = self.data.get("report", {})
        key = "info"
        if key in report:
            self.info = report.get(key, None) or {}
            del report[key]

    def _get_meta(
        self,
    ) -> None:
        logger.debug("_get_meta")

        # ----------------------
        k1 = "report"
        if k1 not in self.data:
            msg = f"Missing '{k1}' key in the json data, this is not a 'report.rl.json' type file"
            raise ValueError(msg)
        report = self.data.get("report", None) or {}

        # ----------------------
        k2 = "metadata"
        if k2 not in report:
            msg = f"Missing '{k1}.{k2}' key in the json data, this is not a 'report.rl.json' type file"
            raise ValueError(msg)
        metadata = report.get("metadata", None) or {}

        # ----------------------
        for name in self.known_metadata_sub_keys:
            setattr(self, name, metadata.pop(name, None) or {})

    def _add_to_results(
        self,
        *,
        cve: str | None,
        comp_uuid: str,
        cve_info_node_instance: CveInfoNode | None,
        dep_uuid: str | None = None,
    ) -> None:
        logger.debug("_add_to_results")

        if cve_info_node_instance is None:
            return

        # prep empty keys
        if cve not in self._results:
            self._results[cve] = {}

        if comp_uuid not in self._results[cve]:
            self._results[cve][comp_uuid] = {}

        # put the data in
        logger.debug("add to results: %s, %s, %s", cve, comp_uuid, dep_uuid)
        if dep_uuid not in self._results[cve][comp_uuid]:
            logger.debug("add cve_info_node_instance: %s", cve_info_node_instance)
            self._results[cve][comp_uuid][dep_uuid] = cve_info_node_instance

    def _get_sha256(
        self,
        data: dict[str, Any],
        what: str = "sha256",
    ) -> str | None:
        logger.debug("_get_%s", what)

        # all components are derived from unpacked files and so have a hash set: we need the sha256
        h = data.get("hashes") or []
        for item in h:
            if isinstance(item, list) and len(item) >= 2:
                if item[0] == what:
                    return str(item[1])
        return None

    def _score_to_severity(
        self,
        *,
        score: float,
        version: int = 3,
    ) -> str:
        logger.debug("_score_to_severity")

        # version 3.x and 4.0 map the same
        # version 2 has no Critical and maps 0 to Low

        if version == 2:
            if score >= 7:
                return self.severity_map[4]
            if score >= 4:
                return self.severity_map[3]
            return self.severity_map[2] if score >= 0 else self.severity_map[1]

        if score >= 9:
            return self.severity_map[5]
        if score >= 7:
            return self.severity_map[4]
        if score >= 4:
            return self.severity_map[3]
        if score > 0:
            return self.severity_map[2]
        return self.severity_map[1]

    def _do_purl(self, purl: str | None) -> str | None:
        if purl:
            try:
                p = PackageURL.from_string(purl)
            except ValueError:
                logger.warning("unparsable purl, ignoring: %r", purl)
            else:
                return f"{p.namespace}/{p.name}" if p.namespace else p.name

        return None

    def _use_path_or_name(
        self,
        *,
        data: dict[str, Any],
        purl: str | None = None,
        name_first: bool = False,
        prefer_path: bool = True,
    ) -> str:
        logger.debug("_use_path_or_name")

        # path or name may be empty so look for the non empty one
        # with name_first we first look at the name
        # with prefer path we use path if it is not empty
        # if we have a valid purl
        #   prefer to derive the name from the purl

        name = data.get("name") or ""
        if name_first and len(name) > 0:
            return str(name)

        path = data.get("path") or ""
        if prefer_path and len(path) > 0:
            return str(path)

        s = self._do_purl(purl)
        if s:
            return s

        if name_first:
            if name:
                return str(name)
            if path:
                return str(path)
        else:
            if path:
                return str(path)
            if name:
                return str(name)

        return ""

    def _get_tags_from_cve(self, this_cve: dict[str, Any]) -> list[str]:
        logger.debug("_get_tags_from_cve")

        tags: list[str] = []
        exploit = this_cve.get("exploit") or []
        if len(exploit) == 0:
            return tags  # we have no exploit info so no tags

        # turn cve exploit info into tags
        for key in exploit:
            if key in self.ignored_exploit_keys:
                continue

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
        logger.debug("_make_impact_from_tags")

        if not impact:
            impact = ""

        for tag in self.impact_sort_order:
            if tag in tags:
                impact += tag + "\n"

        return impact

    def _make_new_cve_info_node(
        self,
        *,
        cve: str,
        active: Any,
        comp_uuid: str,
        dep_uuid: str | None = None,
    ) -> tuple[CveInfoNode | None, dict[str, Any] | None]:
        """Collect all info we can extract from the cve and put in in the CveInfoNode"""
        logger.debug("_make_new_cve_info_node")

        this_cve = self.vulnerabilities.get(cve)
        if this_cve is None:
            logger.error("missing cve info for: %s", cve)
            return None, None

        cve_info_node_instance = CveInfoNode()
        cve_info_node_instance.cve = cve
        cve_info_node_instance.comp_uuid = comp_uuid
        cve_info_node_instance.dep_uuid = dep_uuid
        cve_info_node_instance.active = bool(active)

        # report.info.file is not needed to build a finding: a report without it, or without
        # its sha256, still yields every finding. It used to abort the whole import here.
        cve_info_node_instance.scan_date = self.scan_date

        # score related
        # the version field in the cve dict is int normally
        # lets downscale to int on all cases, we only use v3 and v4 data.
        cvss = this_cve.get("cvss", None) or {}
        cvss_version = cvss.get("version") or 0.0
        cve_info_node_instance.cvss_version = int(float(cvss_version))
        score: float = float(cvss.get("baseScore") or 0.0)

        cve_info_node_instance.score = score
        cve_info_node_instance.score_severity = self._score_to_severity(
            score=score,
            version=cve_info_node_instance.cvss_version,
        )

        cve_info_node_instance.tags = self._get_tags_from_cve(this_cve)
        cve_info_node_instance.impact = self._make_impact_from_tags(
            cve_info_node_instance.tags,
            cve_info_node_instance.impact,
        )

        if "Patching Mandated" in cve_info_node_instance.tags:
            cve_info_node_instance.known_exploited = True

        return cve_info_node_instance, this_cve

    @staticmethod
    def _version(version: Any, purl: str | None) -> str:
        # Spectra Assure reports the version "Generic" for a file without a version of its own;
        # without a purl there is no package identity either, so that is no version
        v = str(version or "")
        if not purl and v.casefold() == "generic":
            return ""
        return v

    def _get_component_purl(
        self,
        component: dict[str, Any],
    ) -> str:
        logger.debug("_get_component_purl")
        ii = component.get("identity") or {}
        return str(ii.get("purl", ""))

    def _get_dependency_purl(
        self,
        dependency: dict[str, Any],
    ) -> str:
        logger.debug("_get_dependency_purl")

        return str(dependency.get("purl", ""))

    def _do_one_cve_component_without_dependencies(
        self,
        *,
        comp_uuid: str,
        component: dict[str, Any],
        cve: str,
        active: Any,
    ) -> CveInfoNode | None:
        logger.debug("_do_one_cve_component_without_dependencies: %s; cve: %s", comp_uuid, cve)

        # one: component -> cve
        # the cve part (now we have one component and one vulnerability)

        cve_info_node_instance, this_cve = self._make_new_cve_info_node(
            cve=cve,
            active=active,
            comp_uuid=comp_uuid,
        )
        if cve_info_node_instance is None:
            return None

        c_purl = self._get_component_purl(component=component)
        version = self._version((component.get("identity") or {}).get("version"), c_purl)
        name = component.get("name", "")
        summary: str | None = this_cve.get("summary") if this_cve else None

        cve_info_node_instance.component_file_path = self._use_path_or_name(data=component, purl=c_purl)
        comp_sha256 = self._get_sha256(data=component)
        if comp_sha256:
            cve_info_node_instance.component_file_sha256 = comp_sha256

        cve_info_node_instance.component_file_purl = c_purl
        cve_info_node_instance.component_file_version = version
        cve_info_node_instance.component_file_name = name
        cve_info_node_instance.component_type = "component"
        cve_info_node_instance.component_name = self._use_path_or_name(data=component, purl=c_purl, name_first=True)
        cve_info_node_instance.component_version = version
        cve_info_node_instance.component_purl = c_purl
        cve_info_node_instance.make_title_cin(cve=cve)
        cve_info_node_instance.make_description_cin(purl=c_purl, summary=summary)
        cve_info_node_instance.vuln_id_from_tool = cve

        logger.debug("%s", cve_info_node_instance)

        return cve_info_node_instance

    def _get_all_active_cve_on_components_without_dependencies(
        self,
    ) -> None:
        # all: component -> cve
        # the component part, could have many vulnerabilities
        logger.debug("_get_all_active_cve_on_components_without_dependencies")

        for comp_uuid, component in self.components.items():
            i_ = component.get("identity", None) or {}
            v = i_.get("vulnerabilities", None)
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
        *,
        comp_uuid: str,
        component: dict[str, Any],
        dep_uuid: str,
        dependency: dict[str, Any],
        cve: str,
        active: Any,
    ) -> CveInfoNode | None:
        logger.debug("_do_one_cve_component_dependency: %s; dep: %s; cve: %s", comp_uuid, dep_uuid, cve)

        # one: component -> dependency -> cve
        # the cve part (now we have one component, one dependency, one vulnerability)

        cve_info_node_instance, this_cve = self._make_new_cve_info_node(
            cve=cve,
            active=active,
            comp_uuid=comp_uuid,  # component
            dep_uuid=dep_uuid,  # dependency
        )
        if cve_info_node_instance is None:
            return None

        c_purl = self._get_component_purl(component=component)
        version = self._version((component.get("identity") or {}).get("version"), c_purl)
        name = component.get("name", "")
        summary: str | None = this_cve.get("summary") if this_cve else None

        cve_info_node_instance.component_file_path = self._use_path_or_name(data=component, purl=c_purl)
        comp_sha256 = self._get_sha256(data=component)
        if comp_sha256:
            cve_info_node_instance.component_file_sha256 = comp_sha256

        cve_info_node_instance.component_file_purl = c_purl
        cve_info_node_instance.component_file_version = version
        cve_info_node_instance.component_file_name = name
        cve_info_node_instance.component_type = "dependency"
        cve_info_node_instance.component_name = dependency.get(
            "product",
            f"no_{cve_info_node_instance.component_type}_product_provided",
        )
        d_purl = self._get_dependency_purl(dependency=dependency)
        cve_info_node_instance.component_version = self._version(
            dependency.get("version", f"no_{cve_info_node_instance.component_type}_version_provided"),
            d_purl,
        )
        cve_info_node_instance.component_purl = d_purl
        cve_info_node_instance.make_title_cin(cve=cve)
        cve_info_node_instance.make_description_cin(purl=d_purl, summary=summary)
        cve_info_node_instance.vuln_id_from_tool = cve

        logger.debug("%s", cve_info_node_instance)
        return cve_info_node_instance

    def _get_one_active_cve_component_dependency(
        self,
        *,
        comp_uuid: str,
        component: dict[str, Any],
        dep_uuid: str,
    ) -> None:
        logger.debug("_get_one_active_cve_component_dependency")

        # one: component -> dependency -> cve
        # the dependency (could have many vulnerabilties)

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
        for cve in v.get("active", []):  # active is a list of CVE_strings
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
        logger.debug("_get_all_active_cve_on_components_with_dependencies")

        # all: component -> dependency -> cve
        # the component part

        for comp_uuid, component in self.components.items():
            i_ = component.get("identity", None) or {}
            d = i_.get("dependencies", None)
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

    def _find_severity_string(self, severity: str) -> str:
        logger.debug("_find_severity_string")

        for s in self.severity_map.values():
            if severity.lower() == s.lower():
                return s
        logger.warning("unmapped violation severity %r, defaulting to Info", severity)
        return self.severity_map[1]  # "Info"

    def _filter_violations_failed_of_category(
        self,
        category: str,
    ) -> dict[str, dict[str, Any]]:
        logger.debug("_filter_violations_failed_of_category")

        dd: dict[str, dict[str, Any]] = {}
        for k, viol in self.violations.items():
            # filter for relevant
            s = viol.get("status", "")
            if s != "fail":
                continue

            c = viol.get("category")
            if not c or c != category:
                continue

            logger.debug("violation: %s", viol)

            r_ = viol.get("references", None) or {}
            c_ = r_.get("component", None) or []
            for comp_uuid in c_:
                logger.debug("component_uuid: %s", comp_uuid)
                comp = self.components.get(comp_uuid)
                if not comp:
                    continue  # missing components, ignore for now

                logger.debug("component: %s", comp)

                # we have a relevant entry

                rr: dict[str, Any] = {}

                rr["status"] = s
                rr["category"] = c
                rr["rule_id"] = viol.get("rule_id")
                rr["description"] = viol.get("description")
                rr["score_severity"] = self._find_severity_string(viol.get("severity", ""))
                rr["score"] = None
                rr["comp_uuid"] = comp_uuid
                rr["comp_class_result"] = comp.get("classification", {}).get("result")
                rr["comp_sha256"] = self._get_sha256(comp)
                rr["name"] = comp.get("name")
                rr["version"] = self._version((comp.get("identity") or {}).get("version"), self._get_component_purl(comp))
                rr["name_or_path"] = self._use_path_or_name(data=comp)

                dd[f"{k};{comp_uuid}"] = rr
        return dd

    def _make_simple_title(
        self,
        data: dict[str, Any],
    ) -> str:
        logger.debug("_make_simple_title")

        rr: list[str] = [
            data["description"],
            f"({data['category']})",
            f"on {data['name']}",
        ]

        tag = sha256_tag(data.get("comp_sha256"))
        if tag:
            rr.append(tag)

        return " ".join(rr)

    def _make_simple_description(self, data: dict[str, Any], category: str | None = None) -> str:
        logger.debug("_make_simple_description")

        rr: list[str] = []  # title will be added to the description on dojo insert by the parser module
        if data["comp_class_result"] and category == "threats":
            rr.append(f"Threat name: {data['comp_class_result']}")
        return " ".join(rr)

    def _make_simple_node(
        self,
        data: dict[str, Any],
        category: str,
    ) -> CveInfoNode:
        logger.debug("_make_simple_node")

        cve_info_node_instance = CveInfoNode()
        cve_info_node_instance.active = True

        my_id = f"{data['category']}-{data['rule_id']}"

        cve_info_node_instance.scan_date = self.scan_date

        cve_info_node_instance.component_file_path = data["name_or_path"]
        if data["comp_sha256"]:
            cve_info_node_instance.component_file_sha256 = data["comp_sha256"]

        cve_info_node_instance.component_file_name = data["name"]
        cve_info_node_instance.component_type = "component"
        cve_info_node_instance.component_name = data["name"]
        cve_info_node_instance.component_file_version = data["version"]
        cve_info_node_instance.component_version = data["version"]  # as for vulnerabilities: the component's version
        cve_info_node_instance.vuln_id_from_tool = my_id

        cve_info_node_instance.title = self._make_simple_title(data)
        cve_info_node_instance.description = self._make_simple_description(data, category)

        cve_info_node_instance.score = data["score"]
        cve_info_node_instance.score_severity = data["score_severity"]

        return cve_info_node_instance

    def _render_secrets_as_text(
        self,
        secrets: dict[str, SecretInfo],
    ) -> str:
        lines: list[str] = []
        for item in secrets.values():
            timestamp = item["timestamp"]
            service = item["service"]
            exposed = item["exposed"]
            line = f"service: {service}, timestamp: {timestamp}, exposed: {exposed}"
            lines.append(line)

            for ev in item["evidence"]:
                canary = ev["canary"]
                liveness = ev["liveness"]
                file_offset = ev["file_offset"]
                line_number = ev["line_number"]
                line = f"liveness: {liveness}"
                if file_offset:
                    line += f", file_offset: {file_offset}"
                if line_number:
                    line += f", line_number: {line_number}"
                if canary:
                    line += f", canary: {canary}"
                lines.append(line)

        return "\n".join(lines)

    def _collect_violations_by_category_secrets(self) -> None:
        logger.debug("_collect_violations_by_category_secrets")
        category = "secrets"

        se = SecretsExtractor(
            components=self.components,
            secrets=self.secrets,
            violations=self.violations,
        )
        st: SecretsTree = se.extract()

        result_dict = self._filter_violations_failed_of_category(category)
        for k, item in result_dict.items():
            logger.debug("violations_by_category: %s %s: %s", category, k, item)
            viol_uuid, comp_uuid = k.split(";")
            secret_as_text = ""
            vi: ViolationInfo | None = st["violations"].get(viol_uuid)
            if vi:
                ci: ComponentInfo | None = vi["components"].get(comp_uuid)
                if ci:
                    si = ci["secrets"]
                    secret_as_text = self._render_secrets_as_text(si)

            cve_info_node_instance = self._make_simple_node(item, category)
            if len(secret_as_text):
                cve_info_node_instance.description += f"\n```\n{secret_as_text}\n```"

            self._add_to_results(
                cve=cve_info_node_instance.vuln_id_from_tool,
                comp_uuid=item["comp_uuid"],
                dep_uuid=None,
                cve_info_node_instance=cve_info_node_instance,
            )

    def _collect_violations_by_category_threats(self) -> None:
        logger.debug("_collect_violations_by_category_threats")

        category = "threats"
        result_dict = self._filter_violations_failed_of_category(category)
        for item in result_dict.values():
            logger.debug("violations_by_category: %s %s", category, item)
            cve_info_node_instance = self._make_simple_node(item, category)

            self._add_to_results(
                cve=cve_info_node_instance.vuln_id_from_tool,
                comp_uuid=item["comp_uuid"],
                dep_uuid=None,
                cve_info_node_instance=cve_info_node_instance,
            )

    def _get_cve_active_all(self) -> None:
        """
        A: walk over components with active vulnerabilities
        B: walk over components -> dependencies with active vulnerabilities
        """
        logger.debug("_get_cve_active_all")

        self._get_all_active_cve_on_components_without_dependencies()
        self._get_all_active_cve_on_components_with_dependencies()

    # ==== PUBLIC ======
    def get_results_list(self) -> Iterator[CveInfoNode]:
        logger.debug("get_results_list")

        # self.results[cve][comp_uuid][dep_uuid] -> cve_info_node_instance
        try:
            for components in self._results.values():
                for component in components.values():
                    for cve_info_node_instance in component.values():
                        logger.debug("result: %s", cve_info_node_instance)
                        yield cve_info_node_instance
        except Exception as e:
            msg = f"Exception iterating over results: {e}"
            logger.exception(msg)
            raise ValueError(msg) from e

    def build_findings(self) -> None:
        logger.debug("build_findings")
        self._get_cve_active_all()
        self._collect_violations_by_category_threats()
        self._collect_violations_by_category_secrets()
