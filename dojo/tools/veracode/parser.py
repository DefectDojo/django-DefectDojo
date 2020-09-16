from xml.dom import NamespaceErr
from lxml import etree
from datetime import datetime
from dojo.models import Finding


class VeracodeXMLParser(object):
    ns = {'x': 'https://www.veracode.com/schema/reports/export/1.0'}

    def __init__(self, filename, test):
        ns = self.ns
        xml = etree.parse(filename)
        report_node = xml.xpath('/x:detailedreport', namespaces=self.ns)[0]

        if not report_node:
            raise NamespaceErr(
                'This version of Veracode report is not supported.  '
                'Please make sure the export is formatted using the '
                'https://www.veracode.com/schema/reports/export/1.0 schema.')

        dupes = dict()

        # This assumes `<category/>` only exists with the `<severity/>` nodes.
        for category_node in report_node.xpath('//x:category', namespaces=ns):

            # Mitigation text.
            mitigation_text = ''
            mitigation_text += category_node.xpath('string(x:recommendations/x:para/@text)', namespaces=ns) + "\n\n"
            # Bullet list of recommendations:
            mitigation_text += ''.join(list(map(
                lambda x: '    * ' + x + '\n',
                category_node.xpath('x:recommendations/x:para/x:bulletitem/@text', namespaces=ns))))

            for flaw in category_node.xpath('.//x:staticflaws/x:flaw', namespaces=ns):
                dupe_key = self.__xml_flaw_to_dupekey(flaw)

                # Only process if we didn't do that before.
                if dupe_key not in dupes:
                    # Add to list.
                    dupes[dupe_key] = self.__xml_flaw_to_finding(flaw, mitigation_text, test)

        self.items = list(dupes.values())

    @classmethod
    def __xml_flaw_to_dupekey(cls, xml_node):
        severity = cls.__xml_flaw_to_severity(xml_node)
        try:
            dupe_key = severity + xml_node.attrib['cweid'] + xml_node.attrib['module'] + xml_node.attrib['type'] + \
                       xml_node.attrib['line'] + xml_node.attrib['issueid']
        except:
            dupe_key = severity + xml_node.attrib['cweid'] + xml_node.attrib['module'] + xml_node.attrib['type'] + \
                       xml_node.attrib['issueid']
        return dupe_key

    @classmethod
    def __xml_flaw_to_severity(cls, xml_node):
        vc_severity_mapping = {
            1: 'Info',
            2: 'Low',
            3: 'Medium',
            4: 'High',
            5: 'Critical'
        }
        return vc_severity_mapping.get(xml_node.attrib['severity'], 'Info')

    @classmethod
    def __xml_flaw_to_finding(cls, xml_node, mitigation_text, test):
        ns = cls.ns

        # Defaults
        finding = Finding()
        finding.test = test
        finding.mitigation = mitigation_text
        finding.verified = False
        finding.active = False
        finding.static_finding = True
        finding.dynamic_finding = False

        # Report values
        finding.severity = cls.__xml_flaw_to_severity(xml_node)
        finding.numerical_severity = Finding.get_numerical_severity(finding.severity)
        finding.cwe = int(xml_node.attrib['cweid'])
        finding.title = '[' + xml_node.attrib['issueid'] + '] ' + xml_node.attrib['categoryname']
        finding.impact = 'CIA Impact: ' + xml_node.attrib['cia_impact'].upper()

        _description = xml_node.attrib['description'].replace('. ', '.\n')
        finding.description = _description \
            + "\n\nVulnerable Module: " \
            + xml_node.attrib['module'] + ' Type: ' \
            + xml_node.attrib['type'] + ' Issue ID: ' \
            + xml_node.attrib['issueid']

        _references = 'None'
        if 'References:' in _description:
            _references = _description[_description.index(
                'References:') + 13:].replace(')  ', ')\n')
        finding.references = _references

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
            _is_mitigated = True
            _mitigated_date = datetime.strptime(
                xml_node.xpath('string(.//x:mitigations/x:mitigation[last()]/@date)', namespaces=ns),
                '%Y-%m-%d %H:%M:%S %Z')
        finding.is_Mitigated = _is_mitigated
        finding.mitigated = _mitigated_date
        finding.active = not _is_mitigated

        # Check if it's a FP in veracode.
        # Only check in case finding was mitigated, since DD doesn't allow
        # both `verified` and `false_p` to be true, while `verified` is implied on the import
        # level, not on the finding-level.
        _false_positive = False
        if _is_mitigated:
            _remediation_status = xml_node.xpath('string(@remediation_status)', namespaces=ns).lower()
            if "false positive" in _remediation_status or "falsepositive" in _remediation_status:
                _false_positive = True
        finding.false_p = _false_positive

        _line_number = xml_node.xpath('string(@line)')
        finding.line = _line_number if _line_number else None
        finding.line_number = finding.line
        finding.sast_source_line = finding.line

        _source_file = xml_node.xpath('string(@sourcefile)')
        finding.file_path = _source_file if _source_file else None
        finding.sourcefile = finding.file_path
        finding.sast_source_file_path = finding.file_path

        _component = xml_node.xpath('string(@module)') + ': ' + xml_node.xpath('string(@scope)')
        finding.component_name = _component if _component != ': ' else None

        _sast_source_obj = xml_node.xpath('string(@functionprototype)')
        finding.sast_source_object = _sast_source_obj if _sast_source_obj else None

        return finding
