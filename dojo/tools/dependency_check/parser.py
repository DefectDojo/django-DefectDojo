import datetime
import hashlib
import logging
import re

import dateutil
from cpe import CPE
from defusedxml import ElementTree
from django.conf import settings
from packageurl import PackageURL

from dojo.models import Finding
from dojo.tools.locations import LocationData
from dojo.utils import parse_cvss_data

logger = logging.getLogger(__name__)


class DependencyCheckParser:
    SEVERITY_MAPPING = {
        "info": "Info",
        "low": "Low",
        "moderate": "Medium",
        "medium": "Medium",
        "high": "High",
        "critical": "Critical",
    }

    CVSS_V3_MAPPINGS = {
        "attackVector": {
            "NETWORK": "N",
            "ADJACENT": "A",
            "LOCAL": "L",
            "PHYSICAL": "P",
            "N": "N",
            "A": "A",
            "L": "L",
            "P": "P",
        },
        "attackComplexity": {"LOW": "L", "HIGH": "H", "L": "L", "H": "H"},
        "privilegesRequired": {
            "NONE": "N",
            "LOW": "L",
            "HIGH": "H",
            "N": "N",
            "L": "L",
            "H": "H",
        },
        "userInteraction": {"NONE": "N", "REQUIRED": "R", "N": "N", "R": "R"},
        "scope": {"UNCHANGED": "U", "CHANGED": "C", "U": "U", "C": "C"},
        "confidentialityImpact": {
            "NONE": "N",
            "LOW": "L",
            "HIGH": "H",
            "N": "N",
            "L": "L",
            "H": "H",
        },
        "integrityImpact": {
            "NONE": "N",
            "LOW": "L",
            "HIGH": "H",
            "N": "N",
            "L": "L",
            "H": "H",
        },
        "availabilityImpact": {
            "NONE": "N",
            "LOW": "L",
            "HIGH": "H",
            "N": "N",
            "L": "L",
            "H": "H",
        },
    }

    def add_finding(self, finding, dupes):
        key_str = "|".join(
            [
                str(finding.title),
                str(finding.cwe),
                str(finding.file_path).lower(),
            ],
        )
        key = hashlib.sha256(key_str.encode("utf-8")).hexdigest()
        if key not in dupes:
            dupes[key] = finding

    def build_related_dependencies_block(self, dependency, namespace):
        """
        Return a markdown block listing related dependencies, or ''.

        Dependency-Check's DependencyBundlingAnalyzer merges co-grouped artifacts
        into one main dependency and lists the others under <relatedDependencies>.
        The vulnerability is attached only to the main dependency in the XML; the
        related entries are metadata pointing to other files in the same logical
        component. Previously we emitted one finding per related entry, which
        multiplied a single CVE into N findings sharing the same title and CVE
        with only the file_path differing — pure noise for the user. Instead we
        keep one finding for the main dependency and surface the related file
        paths in its description.

        DC bundles dependencies under five scenarios (see
        DependencyBundlingAnalyzer.evaluateDependencies):

        1. hashesMatch — identical content (same sha1) found at multiple paths,
           e.g. the same jar packaged into multiple ear/war archives.
        2. isShadedJar — a .jar and a pom.xml extracted from inside it share the
           same CPE; the pom.xml is recorded as related to the jar.
        3. isWebJar — a .js file extracted from a WebJar matches the jar's CPE
           (mapped via pkg:maven/org.webjars/<name>@<version>); the js is
           related to the jar.
        4. CPE + base path + vulnerabilities + filename match — sibling artifacts
           in the same project that share a CPE (e.g. spring-boot,
           spring-boot-actuator, spring-boot-starter all map to the
           spring_boot CPE).
        5. NPM same name + version — the same npm package discovered via
           different resolution paths (e.g. package-lock.json + node_modules).

        Scenario 1 is the only case where the related entries are genuinely
        separate vulnerable locations; scenarios 2-5 are different files
        representing one logical component. Listing all related paths in the
        description preserves the per-location information for scenario 1 while
        removing the noise from scenarios 2-5.
        """
        related = dependency.find(namespace + "relatedDependencies")
        if related is None:
            return ""
        entries = []
        for rd in related.findall(namespace + "relatedDependency"):
            file_name = rd.findtext(f"{namespace}fileName")
            if not file_name:
                continue
            file_path = (rd.findtext(f"{namespace}filePath") or "").strip()
            entries.append(f"- {file_name} ({file_path})" if file_path else f"- {file_name}")
        if not entries:
            return ""
        return "\n**Related Filepaths:**\n" + "\n".join(entries)

    def get_filename_and_path_from_dependency(
        self,
        dependency,
        related_dependency,
        namespace,
    ):
        if related_dependency is None:
            return dependency.findtext(
                f"{namespace}fileName",
            ), dependency.findtext(f"{namespace}filePath")
        if related_dependency.findtext(f"{namespace}fileName"):
            return related_dependency.findtext(
                f"{namespace}fileName",
            ), related_dependency.findtext(f"{namespace}filePath")
        # without filename, it would be just a duplicate finding so we have to skip it. filename
        # is only present for relateddependencies since v6.0.0
        # logger.debug('related_dependency: %s',
        # ElementTree.tostring(related_dependency, encoding='utf8', method='xml'))
        return None, None

    def get_component_name_and_version_from_dependency(
        self,
        dependency,
        related_dependency,
        namespace,
    ):
        identifiers_node = dependency.find(namespace + "identifiers")
        if identifiers_node is not None:
            # analyzing identifier from the more generic to
            package_node = identifiers_node.find(".//" + namespace + "package")
            if package_node is not None:
                pck_id = package_node.findtext(f"{namespace}id").strip()
                purl = PackageURL.from_string(pck_id)
                purl_parts = purl.to_dict()
                component_name = (
                    purl_parts["namespace"] + ":"
                    if purl_parts["namespace"] and len(purl_parts["namespace"]) > 0
                    else ""
                )
                component_name += purl_parts["name"] if purl_parts["name"] and len(purl_parts["name"]) > 0 else ""
                component_name = component_name or None
                component_version = (
                    purl_parts["version"] if purl_parts["version"] and len(purl_parts["version"]) > 0 else ""
                )
                return component_name, component_version, pck_id

            # vulnerabilityIds_node = identifiers_node.find('.//' + namespace + 'vulnerabilityIds')
            # if vulnerabilityIds_node:
            #     id = vulnerabilityIds_node.findtext(f'{namespace}id')
            #     cpe = CPE(id)
            #     component_name = cpe.get_vendor()[0] + ':' if len(cpe.get_vendor()) > 0 else ''
            #     component_name += cpe.get_product()[0] if len(cpe.get_product()) > 0 else ''
            #     component_name = component_name if component_name else None
            #     component_version = cpe.get_version()[0] if len(cpe.get_version()) > 0 else None
            #     return component_name, component_version

            cpe_node = identifiers_node.find(
                ".//" + namespace + 'identifier[@type="cpe"]',
            )
            if cpe_node:
                cpe_id = cpe_node.findtext(f"{namespace}name")
                cpe = CPE(cpe_id)
                component_name = cpe.get_vendor()[0] + ":" if len(cpe.get_vendor()) > 0 else ""
                component_name += cpe.get_product()[0] if len(cpe.get_product()) > 0 else ""
                component_name = component_name or None
                component_version = cpe.get_version()[0] if len(cpe.get_version()) > 0 else None
                return component_name, component_version, None

            maven_node = identifiers_node.find(
                ".//" + namespace + 'identifier[@type="maven"]',
            )
            if maven_node is not None:
                maven_parts = maven_node.findtext(f"{namespace}name").split(
                    ":",
                )
                # logger.debug('maven_parts:' + str(maven_parts))
                if len(maven_parts) == 3:
                    component_name = maven_parts[0] + ":" + maven_parts[1]
                    component_version = maven_parts[2]
                    return component_name, component_version, None

        # TODO: what happens when there multiple evidencecollectednodes with
        # product or version as type?
        evidence_collected_node = dependency.find(
            namespace + "evidenceCollected",
        )
        if evidence_collected_node is not None:
            # <evidenceCollected>
            # <evidence type="product" confidence="HIGH">
            #     <source>file</source>
            #     <name>name</name>
            #     <value>jquery</value>
            # </evidence>
            # <evidence type="version" confidence="HIGH">
            #     <source>file</source>
            #     <name>version</name>
            #     <value>3.1.1</value>
            # </evidence>'
            # will find the first product and version node. if there are multiple it may not pick the best
            # since 6.0.0 howoever it seems like there's always a packageurl above so not sure if we need the effort to
            # implement more logic here
            product_node = evidence_collected_node.find(
                ".//" + namespace + 'evidence[@type="product"]',
            )
            if product_node is not None:
                component_name = product_node.findtext(f"{namespace}value")
                component_version = None
                version_node = evidence_collected_node.find(
                    ".//" + namespace + 'evidence[@type="version"]',
                )
                if version_node is not None:
                    component_version = version_node.findtext(
                        f"{namespace}value",
                    )

                return component_name, component_version, None

        return None, None, None

    def get_severity_and_cvss_meta(self, vulnerability, namespace) -> dict:
        # Get the base severity from the report
        severity = vulnerability.findtext(f"{namespace}severity")
        cvssv3 = None
        cvssv3_score = None
        # Attempt to add the CVSSv3 score, and update the severity accordingly
        if (cvssv3_node := vulnerability.find(namespace + "cvssV3")) is not None:
            try:
                vector_parts = [
                    f"AV:{self.CVSS_V3_MAPPINGS['attackVector'][cvssv3_node.findtext(f'{namespace}attackVector')]}",
                    f"AC:{self.CVSS_V3_MAPPINGS['attackComplexity'][cvssv3_node.findtext(f'{namespace}attackComplexity')]}",
                    f"PR:{self.CVSS_V3_MAPPINGS['privilegesRequired'][cvssv3_node.findtext(f'{namespace}privilegesRequired')]}",
                    f"UI:{self.CVSS_V3_MAPPINGS['userInteraction'][cvssv3_node.findtext(f'{namespace}userInteraction')]}",
                    f"S:{self.CVSS_V3_MAPPINGS['scope'][cvssv3_node.findtext(f'{namespace}scope')]}",
                    f"C:{self.CVSS_V3_MAPPINGS['confidentialityImpact'][cvssv3_node.findtext(f'{namespace}confidentialityImpact')]}",
                    f"I:{self.CVSS_V3_MAPPINGS['integrityImpact'][cvssv3_node.findtext(f'{namespace}integrityImpact')]}",
                    f"A:{self.CVSS_V3_MAPPINGS['availabilityImpact'][cvssv3_node.findtext(f'{namespace}availabilityImpact')]}",
                ]
                version = cvssv3_node.findtext("version") or "3.1"
                vector = f"CVSS:{version}/" + "/".join(vector_parts)
                if cvss_data := parse_cvss_data(vector):
                    cvssv3 = cvss_data.get("cvssv3")
                    cvssv3_score = cvss_data.get("cvssv3_score")
                    severity = cvss_data.get("severity")
            except Exception as e:
                # Only log the error - there is not much we can do to recover from this
                logger.debug(e)
        elif (cvssv2_node := vulnerability.find(namespace + "cvssV2")) is not None:
            severity = cvssv2_node.findtext(f"{namespace}severity").lower().capitalize()

        # handle if the severity have something not in the mapping
        # default to 'Medium' and produce warnings in logs
        if severity:
            if severity.strip().lower() not in self.SEVERITY_MAPPING:
                logger.warning(
                    "Warning: Unknow severity value detected '%s'. Bypass to 'Medium' value",
                    severity,
                )
                severity = "Medium"
            else:
                severity = self.SEVERITY_MAPPING[severity.strip().lower()]
        else:
            severity = "Medium"

        return {
            "severity": severity,
            "cvssv3": cvssv3,
            "cvssv3_score": cvssv3_score,
        }

    def get_finding_from_vulnerability(
        self,
        dependency,
        related_dependency,
        vulnerability,
        test,
        namespace,
    ):
        (
            dependency_filename,
            dependency_filepath,
        ) = self.get_filename_and_path_from_dependency(
            dependency,
            related_dependency,
            namespace,
        )
        # logger.debug('dependency_filename: %s', dependency_filename)

        if dependency_filename is None:
            return None

        tags = []
        mitigated = None
        is_Mitigated = False
        name = vulnerability.findtext(f"{namespace}name")
        cwe_fields = []
        if (cwes_node := vulnerability.find(f"{namespace}cwes")) is not None:
            cwe_fields = [
                cwe_node.text for cwe_node in cwes_node.findall(f"{namespace}cwe") if cwe_node.text
            ]
            cwe_field = cwe_fields[0] if cwe_fields else None
        else:
            cwe_field = vulnerability.findtext(f"{namespace}cwe")
            if cwe_field:
                cwe_fields = [cwe_field]

        description = vulnerability.findtext(f"{namespace}description")

        source = vulnerability.get("source")
        if source:
            description += "\n**Source:** " + str(source)

        # I need the notes field since this is how the suppression is
        # documented.
        notes = vulnerability.findtext(f".//{namespace}notes")

        vulnerability_id = name[:28]
        if vulnerability_id and not vulnerability_id.startswith("CVE"):
            # for vulnerability sources which have a CVE, it is the start of the 'name'.
            # for other sources, we have to set it to None
            vulnerability_id = None

        # Use CWE-1035 as fallback
        cwe = 1035  # Vulnerable Third Party Component
        parsed_cwes = []
        for cwe_value in cwe_fields:
            m = re.match(r"^(CWE-)?(\d+)", cwe_value)
            if m:
                parsed_cwes.append(int(m.group(2)))
        if parsed_cwes:
            cwe = parsed_cwes[0]

        (
            component_name,
            component_version,
            component_purl,
        ) = self.get_component_name_and_version_from_dependency(
            dependency,
            related_dependency,
            namespace,
        )

        stripped_name = name
        # startswith CVE-XXX-YYY
        stripped_name = re.sub(
            r"^CVE-\d{4}-\d{4,7}",
            "",
            stripped_name,
        ).strip()
        # startswith CWE-XXX:
        stripped_name = re.sub(r"^CWE-\d+\:", "", stripped_name).strip()
        # startswith CWE-XXX
        stripped_name = re.sub(r"^CWE-\d+", "", stripped_name).strip()

        if component_name is None:
            logger.warning(
                "component_name was None for File: %s, using dependency file name instead.",
                dependency_filename,
            )
            component_name = dependency_filename

        # some changes in v6.0.0 around CVSS version information
        # https://github.com/jeremylong/DependencyCheck/pull/2781

        reference_detail = None
        references_node = vulnerability.find(namespace + "references")

        if references_node is not None:
            reference_detail = ""
            for reference_node in references_node.findall(
                namespace + "reference",
            ):
                ref_source = reference_node.findtext(f"{namespace}source")
                ref_url = reference_node.findtext(f"{namespace}url")
                ref_name = reference_node.findtext(f"{namespace}name")
                if ref_url == ref_name:
                    reference_detail += f"**Source:** {ref_source}\n**URL:** {ref_url}\n\n"
                else:
                    reference_detail += f"**Source:** {ref_source}\n**URL:** {ref_url}\n**Name:** {ref_name}\n\n"

        if related_dependency is not None:
            tags.append("related")

        if vulnerability.tag == f"{namespace}suppressedVulnerability":
            if notes is None:
                notes = "Document on why we are suppressing this vulnerability is missing!"
                tags.append("no_suppression_document")
            mitigation = f"**This vulnerability is mitigated and/or suppressed:** {notes}\n"
            mitigation += (
                f"Update {component_name}:{component_version} to at least the version recommended in the description"
            )
            mitigated = datetime.datetime.now(datetime.UTC)
            is_Mitigated = True
            active = False
            tags.append("suppressed")

        else:
            mitigation = (
                f"Update {component_name}:{component_version} to at least the version recommended in the description"
            )
            description += "\n**Filepath:** " + str(dependency_filepath)
            active = True

        finding = Finding(
            title=f"{component_name}:{component_version} | {name}",
            file_path=dependency_filename,
            test=test,
            cwe=cwe,
            description=description,
            mitigation=mitigation,
            mitigated=mitigated,
            is_mitigated=is_Mitigated,
            active=active,
            dynamic_finding=False,
            static_finding=True,
            references=reference_detail,
            component_name=component_name,
            component_version=component_version,
            **self.get_severity_and_cvss_meta(vulnerability, namespace),
        )

        if parsed_cwes:
            finding.unsaved_cwes = parsed_cwes

        finding.unsaved_tags = tags

        if settings.V3_FEATURE_LOCATIONS and component_purl:
            finding.unsaved_locations.append(
                LocationData.dependency(purl=component_purl, file_path=dependency_filename),
            )

        if vulnerability_id:
            finding.unsaved_vulnerability_ids = [vulnerability_id]

        return finding

    def get_scan_types(self):
        return ["Dependency Check Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "OWASP Dependency Check output can be imported in Xml format."

    def get_findings(self, filename, test):
        dupes = {}
        namespace = ""
        content = filename.read()
        #  'utf-8' This line is to pass a unittest in test_parsers.TestParsers.test_file_existence.
        scan = ElementTree.fromstring(content)
        regex = r"{.*}"
        matches = re.match(regex, scan.tag)
        try:
            namespace = matches.group(0)
        except BaseException:
            namespace = ""

        dependencies = scan.find(namespace + "dependencies")
        scan_date = None
        if scan.find(f"{namespace}projectInfo") is not None:
            projectInfo_node = scan.find(f"{namespace}projectInfo")
            if projectInfo_node.findtext(f"{namespace}reportDate"):
                scan_date = dateutil.parser.parse(
                    projectInfo_node.findtext(f"{namespace}reportDate"),
                )

        if dependencies is not None:
            for dependency in dependencies.findall(namespace + "dependency"):
                vulnerabilities = dependency.find(
                    namespace + "vulnerabilities",
                )
                if vulnerabilities is not None:
                    related_block = self.build_related_dependencies_block(dependency, namespace)
                    for vulnerability in vulnerabilities.findall(
                        namespace + "vulnerability",
                    ):
                        if vulnerability is not None:
                            finding = self.get_finding_from_vulnerability(
                                dependency,
                                None,
                                vulnerability,
                                test,
                                namespace,
                            )
                            if related_block:
                                finding.description += related_block
                            if scan_date:
                                finding.date = scan_date
                            self.add_finding(finding, dupes)

                    for suppressedVulnerability in vulnerabilities.findall(
                        namespace + "suppressedVulnerability",
                    ):
                        if suppressedVulnerability is not None:
                            finding = self.get_finding_from_vulnerability(
                                dependency,
                                None,
                                suppressedVulnerability,
                                test,
                                namespace,
                            )
                            if related_block:
                                finding.description += related_block
                            if scan_date:
                                finding.date = scan_date
                            self.add_finding(finding, dupes)
                elif settings.V3_FEATURE_LOCATIONS:
                    # Collect product-level dependency locations
                    _, _, component_purl = self.get_component_name_and_version_from_dependency(
                        dependency,
                        None,
                        namespace,
                    )
                    if component_purl:
                        test.unsaved_metadata.append(
                            LocationData.dependency(purl=component_purl),
                        )

        return list(dupes.values())
