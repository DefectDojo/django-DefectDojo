__author__ = 'jay7958'

from xml.dom import NamespaceErr
from defusedxml import ElementTree
from datetime import datetime

from dojo.models import Finding


class VeracodeXMLParser(object):
    def __init__(self, filename, test):
        vscan = ElementTree.parse(filename)
        root = vscan.getroot()

        if 'https://www.veracode.com/schema/reports/export/1.0' not in str(
                root):
            # version not supported
            raise NamespaceErr(
                'This version of Veracode report is not supported.  '
                'Please make sure the export is formatted using the '
                'https://www.veracode.com/schema/reports/export/1.0 schema.')

        dupes = dict()
        severitycount = 0

        for severity in root.iter(
                '{https://www.veracode.com/schema/reports/export/1.0}severity'
        ):
            if severity.attrib['level'] == '5':
                sev = 'Critical'
            elif severity.attrib['level'] == '4':
                sev = 'High'
            elif severity.attrib['level'] == '3':
                sev = 'Medium'
            elif severity.attrib['level'] == '2':
                sev = 'Low'
            else:
                sev = 'Info'

            for category in severity.iter(
                    '{https://www.veracode.com/schema/reports/export/1.0}category'
            ):
                recommendations = category.find(
                    '{https://www.veracode.com/schema/reports/export/1.0}recommendations'
                )
                mitigation = ''
                for para in recommendations.iter(
                        '{https://www.veracode.com/schema/reports/export/1.0}para'
                ):
                    mitigation += para.attrib['text'] + '\n\n'
                    for bullet in para.iter(
                            '{https://www.veracode.com/schema/reports/export/1.0}bulletitem'
                    ):
                        mitigation += "    * " + bullet.attrib['text'] + '\n'

                for flaw in category.iter(
                        '{https://www.veracode.com/schema/reports/export/1.0}flaw'
                ):
                    dupe_key = sev + flaw.attrib['cweid'] + flaw.attrib['module'] + flaw.attrib['type'] + flaw.attrib['line'] + flaw.attrib['issueid']

                    if dupe_key in dupes:
                        find = dupes[dupe_key]
                    else:
                        dupes[dupe_key] = True
                        description = flaw.attrib['description'].replace(
                            '. ', '.\n')
                        if 'References:' in description:
                            references = description[description.index(
                                'References:') + 13:].replace(')  ', ')\n')
                        else:
                            references = 'None'
                        mitigatedTest = 0
                        if 'date_first_occurrence' in flaw.attrib:
                            find_date = datetime.strptime(
                                flaw.attrib['date_first_occurrence'],
                                '%Y-%m-%d %H:%M:%S %Z')
                        else:
                            find_date = test.target_start
                        if 'falsepositive' in flaw.attrib:
                            mitigatedTest = 1
                            for mitigations in flaw.iter(
                                    '{https://www.veracode.com/schema/reports/export/1.0}mitigations'
                            ):
                                for mitigation in mitigations.iter(
                                        '{https://www.veracode.com/schema/reports/export/1.0}mitigation'
                                ):
                                    mitigated = datetime.strptime(
                                        mitigation.attrib.get('date'),
                                        '%Y-%m-%d %H:%M:%S %Z')
                            mitigated_by_id = 4
                        else:
                            pass
                        if mitigatedTest == 1:
                            find = Finding(
                                title=flaw.attrib['categoryname'],
                                line_number=flaw.attrib['line'],
                                file_path=flaw.attrib['sourcefilepath'] + flaw.attrib['sourcefile'],
                                line=flaw.attrib['line'],
                                static_finding=True,
                                sourcefile=flaw.attrib['sourcefile'],
                                cwe=int(flaw.attrib['cweid']),
                                test=test,
                                active=False,
                                verified=False,
                                description=description +
                                "\n\nVulnerable Module: " +
                                flaw.attrib['module'] + ' Type: ' +
                                flaw.attrib['type'] + ' Issue ID: ' +
                                flaw.attrib['issueid'],
                                mitigated=mitigated,
                                mitigated_by_id=mitigated_by_id,
                                severity=sev,
                                numerical_severity=Finding.
                                get_numerical_severity(sev),
                                mitigation=mitigation,
                                impact='CIA Impact: ' +
                                flaw.attrib['cia_impact'].upper(),
                                references=references,
                                url='N/A',
                                date=find_date)
                        else:
                            find = Finding(
                                title=flaw.attrib['categoryname'],
                                line_number=flaw.attrib['line'],
                                file_path=flaw.attrib['sourcefilepath'] + flaw.attrib['sourcefile'],
                                line=flaw.attrib['line'],
                                static_finding=True,
                                sourcefile=flaw.attrib['sourcefile'],
                                cwe=int(flaw.attrib['cweid']),
                                test=test,
                                active=False,
                                verified=False,
                                description=description +
                                "\n\nVulnerable Module: " +
                                flaw.attrib['module'] + ' Type: ' +
                                flaw.attrib['type'] + ' Issue ID: ' +
                                flaw.attrib['issueid'],
                                severity=sev,
                                numerical_severity=Finding.
                                get_numerical_severity(sev),
                                mitigation=mitigation,
                                impact='CIA Impact: ' +
                                flaw.attrib['cia_impact'].upper(),
                                references=references,
                                url='N/A',
                                date=find_date)
                        dupes[dupe_key] = find

        self.items = list(dupes.values())
