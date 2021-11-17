import re
from datetime import datetime

from defusedxml import ElementTree

from dojo.models import Finding
from dojo.models import Endpoint

XML_NAMESPACE = {'x': 'https://www.veracode.com/schema/reports/export/1.0'}


class VeracodeParser(object):
    """This parser is written for Veracode Detailed XML reports, version 1.5.

    Version is annotated in the report, `detailedreport/@report_format_version`.
    see https://help.veracode.com/r/t_download_XML_report
    """

    vc_severity_mapping = {
        1: 'Info',
        2: 'Low',
        3: 'Medium',
        4: 'High',
        5: 'Critical'
    }

    def get_scan_types(self):
        return ["Veracode Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Veracode Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Detailed XML Report"

    def get_findings(self, filename, test):
        root = ElementTree.parse(filename).getroot()

        app_id = root.attrib['app_id']
        report_date = datetime.strptime(root.attrib['last_update_time'], '%Y-%m-%d %H:%M:%S %Z')

        dupes = dict()

        # Get SAST findings
        # This assumes `<category/>` only exists within the `<severity/>` nodes.
        for category_node in root.findall('x:severity/x:category', namespaces=XML_NAMESPACE):

            # Mitigation text.
            mitigation_text = ''
            mitigation_text += category_node.find('x:recommendations/x:para', namespaces=XML_NAMESPACE).get('text') + "\n\n"
            # Bullet list of recommendations:
            mitigation_text += ''.join(list(map(
                lambda x: '    * ' + x.get('text') + '\n',
                category_node.findall('x:recommendations/x:para/x:bulletitem', namespaces=XML_NAMESPACE))))

            for flaw_node in category_node.findall('x:cwe/x:staticflaws/x:flaw', namespaces=XML_NAMESPACE):
                dupe_key = flaw_node.attrib['issueid']

                # Only process if we didn't do that before.
                if dupe_key not in dupes:
                    # Add to list.
                    dupes[dupe_key] = self.__xml_static_flaw_to_finding(app_id, flaw_node, mitigation_text, test)

            for flaw_node in category_node.findall('x:cwe/x:dynamicflaws/x:flaw', namespaces=XML_NAMESPACE):
                dupe_key = flaw_node.attrib['issueid']

                if dupe_key not in dupes:
                    dupes[dupe_key] = self.__xml_dynamic_flaw_to_finding(app_id, flaw_node, mitigation_text, test)

        # Get SCA findings
        for component in root.findall('x:software_composition_analysis/x:vulnerable_components'
                                             '/x:component', namespaces=XML_NAMESPACE):
            _library = component.attrib['library']
            _vendor = component.attrib['vendor']
            _version = component.attrib['version']

            for vulnerability in component.findall('x:vulnerabilities/x:vulnerability', namespaces=XML_NAMESPACE):
                dupe_key = vulnerability.attrib['cve_id']
                # Only process if we didn't do that before.
                if dupe_key not in dupes:
                    dupes[dupe_key] = self.__xml_sca_flaw_to_finding(test, report_date, _vendor, _library, _version, vulnerability)

        return list(dupes.values())

    @classmethod
    def __xml_flaw_to_unique_id(cls, app_id, xml_node):
        issue_id = xml_node.attrib['issueid']
        return 'app-' + app_id + '_issue-' + issue_id

    @classmethod
    def __xml_flaw_to_severity(cls, xml_node):
        return cls.vc_severity_mapping.get(int(xml_node.attrib['severity']), 'Info')

    @classmethod
    def __xml_flaw_to_finding(cls, app_id, xml_node, mitigation_text, test):
        # Defaults
        finding = Finding()
        finding.test = test
        finding.mitigation = mitigation_text
        finding.static_finding = True
        finding.dynamic_finding = False
        finding.unique_id_from_tool = cls.__xml_flaw_to_unique_id(app_id, xml_node)

        # Report values
        finding.severity = cls.__xml_flaw_to_severity(xml_node)
        finding.cwe = int(xml_node.attrib['cweid'])
        finding.title = xml_node.attrib['categoryname']
        finding.impact = 'CIA Impact: ' + xml_node.attrib['cia_impact'].upper()

        # Note that DD's legacy dedupe hashing uses the description field,
        # so for compatibility, description field should contain very static info.
        _description = xml_node.attrib['description'].replace('. ', '.\n')
        finding.description = _description

        _references = 'None'
        if 'References:' in _description:
            _references = _description[_description.index(
                'References:') + 13:].replace(')  ', ')\n')
        finding.references = _references \
            + "\n\nVulnerable Module: " + xml_node.attrib['module'] \
            + "\nType: " + xml_node.attrib['type'] \
            + "\nVeracode issue ID: " + xml_node.attrib['issueid']

        _date_found = test.target_start
        if 'date_first_occurrence' in xml_node.attrib:
            _date_found = datetime.strptime(
                xml_node.attrib['date_first_occurrence'],
                '%Y-%m-%d %H:%M:%S %Z')
        finding.date = _date_found

        _is_mitigated = False
        _mitigated_date = None
        if ('mitigation_status' in xml_node.attrib and
                xml_node.attrib["mitigation_status"].lower() == "accepted"):
            # This happens if any mitigation (including 'Potential false positive')
            # was accepted in VC.
            for mitigation in xml_node.findall("x:mitigations/x:mitigation", namespaces=XML_NAMESPACE):
                _is_mitigated = True
                _mitigated_date = datetime.strptime(mitigation.attrib['date'], '%Y-%m-%d %H:%M:%S %Z')
        finding.is_mitigated = _is_mitigated
        finding.mitigated = _mitigated_date
        finding.active = not _is_mitigated

        # Check if it's a FP in veracode.
        # Only check in case finding was mitigated, since DD doesn't allow
        # both `verified` and `false_p` to be true, while `verified` is implied on the import
        # level, not on the finding-level.
        _false_positive = False
        if _is_mitigated:
            _remediation_status = xml_node.attrib['remediation_status'].lower()
            if "false positive" in _remediation_status or "falsepositive" in _remediation_status:
                _false_positive = True
        finding.false_p = _false_positive

        return finding

    @classmethod
    def __xml_static_flaw_to_finding(cls, app_id, xml_node, mitigation_text, test):
        finding = cls.__xml_flaw_to_finding(app_id, xml_node, mitigation_text, test)
        finding.static_finding = True
        finding.dynamic_finding = False

        _line_number = xml_node.attrib['line']
        _functionrelativelocation = xml_node.attrib['functionrelativelocation']
        if (_line_number is not None and _line_number.isdigit() and
                _functionrelativelocation is not None and _functionrelativelocation.isdigit()):
            finding.line = int(_line_number) + int(_functionrelativelocation)
            finding.sast_source_line = finding.line

        _source_file = xml_node.attrib.get('sourcefile')
        _sourcefilepath = xml_node.attrib.get('sourcefilepath')
        finding.file_path = _sourcefilepath + _source_file
        finding.sast_source_file_path = _sourcefilepath + _source_file

        _sast_source_obj = xml_node.attrib.get('functionprototype')
        finding.sast_source_object = _sast_source_obj if _sast_source_obj else None

        return finding

    @classmethod
    def __xml_dynamic_flaw_to_finding(cls, app_id, xml_node, mitigation_text, test):
        finding = cls.__xml_flaw_to_finding(app_id, xml_node, mitigation_text, test)
        finding.static_finding = False
        finding.dynamic_finding = True

        url_host = xml_node.attrib.get('url')
        finding.unsaved_endpoints = [Endpoint.from_uri(url_host)]

        return finding

    @classmethod
    def __cvss_to_severity(cls, cvss):
        if cvss >= 9:
            return cls.vc_severity_mapping.get(5)
        elif cvss >= 7:
            return cls.vc_severity_mapping.get(4)
        elif cvss >= 4:
            return cls.vc_severity_mapping.get(3)
        elif cvss > 0:
            return cls.vc_severity_mapping.get(2)
        else:
            return cls.vc_severity_mapping.get(1)

    @staticmethod
    def _get_cwe(val):
        # Match only the first CWE!
        cweSearch = re.search("CWE-(\\d+)", val, re.IGNORECASE)
        if cweSearch:
            return int(cweSearch.group(1))
        else:
            return None

    @classmethod
    def __xml_sca_flaw_to_finding(cls, test, report_date, vendor, library, version, xml_node):
        # Defaults
        finding = Finding()
        finding.test = test
        finding.static_finding = True
        finding.dynamic_finding = False
        finding.unique_id_from_tool = xml_node.attrib['cve_id']

        # Report values
        finding.severity = cls.__cvss_to_severity(float(xml_node.attrib['cvss_score']))
        finding.cve = xml_node.attrib['cve_id']
        finding.cwe = cls._get_cwe(xml_node.attrib['cwe_id'])
        finding.title = "Vulnerable component: {0}:{1}".format(library, version)
        finding.component_name = library
        finding.component_version = version

        # Use report-date, otherwise DD doesn't
        # overwrite old matching SCA findings.
        finding.date = report_date

        _description = 'This library has known vulnerabilities.\n'
        _description += \
                "**CVE: [{0}](https://nvd.nist.gov/vuln/detail/{0})** ({1})\n" \
                "CVS Score: {2} ({3})\n" \
                "Summary: \n>{4}" \
                "\n\n-----\n\n".format(
                    xml_node.attrib['cve_id'],
                    xml_node.attrib.get('first_found_date'),
                    xml_node.attrib['cvss_score'],
                    cls.vc_severity_mapping.get(int(xml_node.attrib['severity']), 'Info'),
                    xml_node.attrib['cve_summary'])
        finding.description = _description

        return finding
