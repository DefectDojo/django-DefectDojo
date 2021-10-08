import hashlib
import logging
import re

from cpe import CPE
from defusedxml import ElementTree
from packageurl import PackageURL

from dojo.models import Finding

logger = logging.getLogger(__name__)

SEVERITY = ['Info', 'Low', 'Medium', 'High', 'Critical']


class DependencyCheckParser(object):
    def add_finding(self, finding, dupes):
        if finding is not None:
            key_str = '{}|{}|{}'.format(finding.cve,
                                            finding.cwe,
                                            finding.file_path.lower())
            key = hashlib.md5(key_str.encode('utf-8')).hexdigest()

            if key not in dupes:
                dupes[key] = finding

    def get_field_value(self, parent_node, field_name, namespace):
        field_node = parent_node.find(namespace + field_name)
        field_value = '' if field_node is None else field_node.text
        return field_value

    def get_filename_and_path_from_dependency(self, dependency, related_dependency, namespace):
        if related_dependency:
            if self.get_field_value(related_dependency, 'fileName', namespace):
                return self.get_field_value(related_dependency, 'fileName', namespace), self.get_field_value(related_dependency, 'filePath', namespace)
            else:
                # without filename, it would be just a duplicate finding so we have to skip it. filename is only present for relateddependencies since v6.0.0
                # logger.debug('related_dependency: %s', ElementTree.tostring(related_dependency, encoding='utf8', method='xml'))
                return None, None
        else:
            return self.get_field_value(dependency, 'fileName', namespace), self.get_field_value(dependency, 'filePath', namespace)

    def get_component_name_and_version_from_dependency(self, dependency, related_dependency, namespace):
        component_name, component_version = None, None
        # big try catch to avoid crashint the parser on some unexpected stuff
        try:
            identifiers_node = dependency.find(namespace + 'identifiers')
            if identifiers_node:
                # <identifiers>
                #     <identifier type="cpe" confidence="HIGHEST">
                #         <name>cpe:/a:apache:xalan-java:2.7.1</name>
                #         <url>https://web.nvd.nist.gov/view/vuln/search-results?adv_search=true&amp;cves=on&amp;cpe_version=cpe%3A%2Fa%3Aapache%3Axalan-java%3A2.7.1</url>
                #     </identifier>
                #     <identifier type="maven" confidence="HIGHEST">
                #         <name>xalan:serializer:2.7.1</name>
                #         <url>https://search.maven.org/remotecontent?filepath=xalan/serializer/2.7.1/serializer-2.7.1.jar</url>
                #     </identifier>
                # </identifiers>

                # newly found in v6.0.0
                # <identifiers>
                #     <package confidence="HIGH">
                #         <id>pkg:maven/nl.company.client.offerservice/client-offer-service-codegen@1.0-SNAPSHOT</id>
                #         <url>https://ossindex.sonatype.org/component/pkg:maven/nl.company.client.offerservice/client-offer-service-codegen@1.0-SNAPSHOT</url>
                #     </package>
                # </identifiers>

                # <identifiers>
                #     <package confidence="HIGHEST">
                #         <id>pkg:npm/yargs-parser@5.0.0</id>
                #         <url>https://ossindex.sonatype.org/component/pkg:npm/yargs-parser@5.0.0</url>
                #     </package>
                # </identifiers>

                package_node = identifiers_node.find('.//' + namespace + 'package')
                if package_node:
                    logger.debug('package string: ' + self.get_field_value(package_node, 'id', namespace))
                    id = self.get_field_value(package_node, 'id', namespace)

                    purl = PackageURL.from_string(id)
                    purl_parts = purl.to_dict()
                    component_name = purl_parts['namespace'] + ':' if purl_parts['namespace'] and len(purl_parts['namespace']) > 0 else ''
                    component_name += purl_parts['name'] if purl_parts['name'] and len(purl_parts['name']) > 0 else ''
                    component_name = component_name if component_name else None

                    component_version = purl_parts['version'] if purl_parts['version'] and len(purl_parts['version']) > 0 else ''
                    return component_name, component_version

                cpe_node = identifiers_node.find('.//' + namespace + 'identifier[@type="cpe"]')
                if cpe_node:
                    # logger.debug('cpe string: ' + self.get_field_value(cpe_node, 'name'))
                    cpe = CPE(self.get_field_value(cpe_node, 'name'))
                    component_name = cpe.get_vendor()[0] + ':' if len(cpe.get_vendor()) > 0 else ''
                    component_name += cpe.get_product()[0] if len(cpe.get_product()) > 0 else ''
                    component_name = component_name if component_name else None
                    component_version = cpe.get_version()[0] if len(cpe.get_version()) > 0 else None
                    # logger.debug('get_edition: ' + str(cpe.get_edition()))
                    # logger.debug('get_language: ' + str(cpe.get_language()))
                    # logger.debug('get_part: ' + str(cpe.get_part()))
                    # logger.debug('get_software_edition: ' + str(cpe.get_software_edition()))
                    # logger.debug('get_target_hardware: ' + str(cpe.get_target_hardware()))
                    # logger.debug('get_target_software: ' + str(cpe.get_target_software()))
                    # logger.debug('get_vendor: ' + str(cpe.get_vendor()))
                    # logger.debug('get_update: ' + str(cpe.get_update()))
                    return component_name, component_version

                maven_node = identifiers_node.find('.//' + namespace + 'identifier[@type="maven"]')
                if maven_node:
                    # logger.debug('maven_string: ' + self.get_field_value(maven_node, 'name'))
                    maven_parts = self.get_field_value(maven_node, 'name', namespace).split(':')
                    # logger.debug('maven_parts:' + str(maven_parts))
                    if len(maven_parts) == 3:
                        component_name = maven_parts[0] + ':' + maven_parts[1]
                        component_version = maven_parts[2]
                        return component_name, component_version

                        # TODO
                        # include identifiers in description?
                        # <identifiers>
                        #     <package confidence="HIGH">
                        #         <id>pkg:maven/org.dom4j/dom4j@2.1.1.redhat-00001</id>
                        #         <url>https://ossindex.sonatype.org/component/pkg:maven/org.dom4j/dom4j@2.1.1.redhat-00001</url>
                        #     </package>
                        #     <vulnerabilityIds confidence="HIGHEST">
                        #         <id>cpe:2.3:a:dom4j_project:dom4j:2.1.1.hat-00001:*:*:*:*:*:*:*</id>
                        #         <url>https://nvd.nist.gov/vuln/search/results?form_type=Advanced&amp;results_type=overview&amp;search_type=all&amp;cpe_vendor=cpe%3A%2F%3Adom4j_project&amp;cpe_product=cpe%3A%2F%3Adom4j_project%3Adom4j&amp;cpe_version=cpe%3A%2F%3Adom4j_project%3Adom4j%3A2.1.1.hat-00001</url>
                        #     </vulnerabilityIds>

            # TODO what happens when there multiple evidencecollectednodes with product or version as type?
            evidence_collected_node = dependency.find(namespace + 'evidenceCollected')
            if evidence_collected_node:
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
                product_node = evidence_collected_node.find('.//' + namespace + 'evidence[@type="product"]')
                if product_node:
                    component_name = self.get_field_value(product_node, 'value', namespace)
                    version_node = evidence_collected_node.find('.//' + namespace + 'evidence[@type="version"]')
                    if version_node:
                        component_version = self.get_field_value(version_node, 'value', namespace)

                    return component_name, component_version

        except:
            logger.exception('error parsing component_name and component_version')
            logger.debug('dependency: %s', ElementTree.tostring(dependency, encoding='utf8', method='xml'))

        return component_name, component_version

    def get_finding_from_vulnerability(self, dependency, related_dependency, vulnerability, test, namespace):
        dependency_filename, dependency_filepath = self.get_filename_and_path_from_dependency(dependency, related_dependency, namespace)
        # logger.debug('dependency_filename: %s', dependency_filename)

        tags = []

        if dependency_filename is None:
            return None

        name = self.get_field_value(vulnerability, 'name', namespace)
        cwes_node = vulnerability.find(namespace + 'cwes')
        if cwes_node is not None:
            cwe_field = self.get_field_value(cwes_node, 'cwe', namespace)
        else:
            cwe_field = self.get_field_value(vulnerability, 'cwe', namespace)
        description = self.get_field_value(vulnerability, 'description', namespace)
        # I need the notes field since this is how the suppression is documented.
        notes = self.get_field_value(vulnerability, 'notes', namespace)

        cve = name[:28]
        if cve and not cve.startswith('CVE'):
            # for vulnerability sources which have a CVE, it is the start of the 'name'.
            # for other sources, we have to set it to None
            cve = None

        # Use CWE-1035 as fallback
        cwe = 1035  # Vulnerable Third Party Component
        if cwe_field:
            m = re.match(r"^(CWE-)?(\d+)", cwe_field)
            if m:
                cwe = int(m.group(2))

        component_name, component_version = self.get_component_name_and_version_from_dependency(dependency, related_dependency, namespace)

        stripped_name = name
        # startswith CVE-XXX-YYY
        stripped_name = re.sub(r'^CVE-\d{4}-\d{4,7}', '', stripped_name).strip()
        # startswith CWE-XXX:
        stripped_name = re.sub(r'^CWE-\d+\:', '', stripped_name).strip()
        # startswith CWE-XXX
        stripped_name = re.sub(r'^CWE-\d+', '', stripped_name).strip()

        if component_name is None:
            logger.warning("component_name was None for File: {}, using dependency file name instead.".format(dependency_filename))
            component_name = dependency_filename

        title = '%s:%s | %s(in %s)' % (component_name.split(':')[-1], component_version,
            (stripped_name + ' ' if stripped_name else '') + (description if len(stripped_name) < 25 else ''),
            dependency_filename)

        # some changes in v6.0.0 around CVSS version information
        # https://github.com/jeremylong/DependencyCheck/pull/2781

        cvssv2_node = vulnerability.find(namespace + 'cvssV2')
        cvssv3_node = vulnerability.find(namespace + 'cvssV3')
        severity = self.get_field_value(vulnerability, 'severity', namespace).lower().capitalize()
        if not severity:
            if cvssv3_node is not None:
                severity = self.get_field_value(cvssv3_node, 'baseSeverity', namespace).lower().capitalize()
            elif cvssv2_node is not None:
                severity = self.get_field_value(cvssv2_node, 'severity', namespace).lower().capitalize()

        # https://github.com/DefectDojo/django-DefectDojo/issues/4309
        if severity.lower() == 'moderate':
            severity = 'Medium'

        if severity in SEVERITY:
            severity = severity
        else:
            tag = "Severity is inaccurate : " + str(severity)
            title += " | " + tag
            logger.warn("Warning: Inaccurate severity detected. Setting it's severity to Medium level.\n" + "Title is :" + title)
            severity = "Medium"

        reference_detail = None
        references_node = vulnerability.find(namespace + 'references')

        if references_node is not None:
            reference_detail = ''
            for reference_node in references_node.findall(namespace +
                                                          'reference'):
                name = self.get_field_value(reference_node, 'name', namespace)
                source = self.get_field_value(reference_node, 'source', namespace)
                url = self.get_field_value(reference_node, 'url', namespace)
                reference_detail += 'name: {0}\n' \
                                     'source: {1}\n' \
                                     'url: {2}\n\n'.format(name, source, url)

        if related_dependency is not None:
            tags.append("related")

        if vulnerability.tag == "{}suppressedVulnerability".format(namespace):
            if notes == "":
                notes = "Document on why we are suppressing this vulnerability is missing!"
                tags.append("no_suppression_document")
            mitigation = '**This vulnerability is mitigated and/or suppressed:** {}\n'.format(notes)
            mitigation = mitigation + 'Update {}:{} to at least the version recommended in the description'.format(component_name, component_version)

            active = False
            tags.append("suppressed")

        else:
            mitigation = 'Update {}:{} to at least the version recommended in the description'.format(component_name, component_version)
            description += '\nFilepath: ' + str(dependency_filepath)
            active = True

        return Finding(
            title=title,
            file_path=dependency_filename,
            test=test,
            cwe=cwe,
            cve=cve,
            description=description,
            severity=severity,
            mitigation=mitigation,
            tags=tags,
            active=active,
            static_finding=True,
            references=reference_detail,
            component_name=component_name,
            component_version=component_version)

    def get_scan_types(self):
        return ["Dependency Check Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "OWASP Dependency Check output can be imported in Xml format."

    def get_findings(self, filename, test):
        if filename is None:
            return list()

        dupes = dict()
        namespace = ''
        content = filename.read()

        scan = ElementTree.fromstring(content)
        regex = r"{.*}"
        matches = re.match(regex, scan.tag)
        try:
            namespace = matches.group(0)
        except:
            namespace = ""

        dependencies = scan.find(namespace + 'dependencies')

        if dependencies:
            for dependency in dependencies.findall(namespace + 'dependency'):
                logger.debug('parsing dependency: %s', self.get_field_value(dependency, 'fileName', namespace))
                vulnerabilities = dependency.find(namespace + 'vulnerabilities')
                if vulnerabilities is not None:
                    for vulnerability in vulnerabilities.findall(namespace + 'vulnerability'):
                        if vulnerability:
                            finding = self.get_finding_from_vulnerability(dependency, None, vulnerability, test, namespace)
                            self.add_finding(finding, dupes)

                    for suppressedVulnerability in vulnerabilities.findall(namespace + 'suppressedVulnerability'):
                        if suppressedVulnerability:
                            finding = self.get_finding_from_vulnerability(dependency, None, suppressedVulnerability, test, namespace)
                            self.add_finding(finding, dupes)

                    relatedDependencies = dependency.find(namespace + 'relatedDependencies')
                    if relatedDependencies:
                        for relatedDependency in relatedDependencies.findall(namespace + 'relatedDependency'):
                            finding = self.get_finding_from_vulnerability(dependency, relatedDependency, vulnerability, test, namespace)
                            self.add_finding(finding, dupes)

        return list(dupes.values())

# future idea include vulnerablesoftware in description?
# <vulnerableSoftware>
#     <software>cpe:2.3:a:netapp:snapmanager:-:*:*:*:*:sap:*:*</software>
#     <software versionStartIncluding="18.1.0.0" versionEndIncluding="18.8.19.0">cpe:2.3:a:oracle:primavera_p6_enterprise_project_portfolio_management:*:*:*:*:*:*:*:*</software>
#     <software>cpe:2.3:a:oracle:rapid_planning:12.2:*:*:*:*:*:*:*</software>
#     <software versionStartIncluding="19.12.0.0" versionEndIncluding="19.12.6.0">cpe:2.3:a:oracle:primavera_p6_enterprise_project_portfolio_management:*:*:*:*:*:*:*:*</software>
#     <software>cpe:2.3:a:netapp:snapmanager:-:*:*:*:*:oracle:*:*</software>
#     <software versionStartIncluding="16.1.0.0" versionEndIncluding="16.2.20.1">cpe:2.3:a:oracle:primavera_p6_enterprise_project_portfolio_management:*:*:*:*:*:*:*:*</software>
#     <software>cpe:2.3:a:netapp:oncommand_workflow_automation:-:*:*:*:*:*:*:*</software>
#     <software>cpe:2.3:a:oracle:retail_integration_bus:16.0:*:*:*:*:*:*:*</software>
#     <software versionStartIncluding="2.0.0" versionEndExcluding="2.0.3">cpe:2.3:a:dom4j_project:dom4j:*:*:*:*:*:*:*:*</software>
#     <software vulnerabilityIdMatched="true" versionStartIncluding="2.1.0" versionEndExcluding="2.1.3">cpe:2.3:a:dom4j_project:dom4j:*:*:*:*:*:*:*:*</software>
#     <software>cpe:2.3:a:oracle:retail_integration_bus:15.0:*:*:*:*:*:*:*</software>
#     <software>cpe:2.3:a:netapp:snapcenter:-:*:*:*:*:*:*:*</software>
#     <software versionStartIncluding="17.1.0.0" versionEndIncluding="17.12.17.1">cpe:2.3:a:oracle:primavera_p6_enterprise_project_portfolio_management:*:*:*:*:*:*:*:*</software>
#     <software>cpe:2.3:a:netapp:oncommand_api_services:-:*:*:*:*:*:*:*</software>
#     <software>cpe:2.3:a:oracle:rapid_planning:12.1:*:*:*:*:*:*:*</software>
#     <software>cpe:2.3:a:netapp:snap_creator_framework:-:*:*:*:*:*:*:*</software>
# </vulnerableSoftware>
