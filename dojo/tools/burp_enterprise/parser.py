from lxml import etree
from dojo.models import Finding
import logging
import re

logger = logging.getLogger(__name__)


class BurpEnterpriseHtmlParser(object):

    def __init__(self, filename, test, mode=None):
        parser = etree.HTMLParser()
        tree = etree.parse(filename, parser)
        if(mode in [None, 'detailed']):
            self.mode = mode
        else:
            raise Exception("Internal error: Invalid mode " + mode + ". Expected: one of None, 'detailed'")

        # Dictonary to hold the aggregated findings with:
        #  - key: the concatenated aggregate keys
        #  - value: the finding
        self.dupes = dict()

        self.test = test
        self.impact = "No impact provided"

        if tree:
            self.items = self.get_items(tree)
        else:
            self.items = dict()

    def get_content(self, container):
        # print('\ncontent')
        s = ''
        for elem in container.iterchildren():
            # print(elem.tag, ' : ', elem.text, '\n')
            if elem.text is not None and elem.text.strip() != '':
                if elem.tag == 'a':
                    s += '(' + elem.text + ')[' + elem.attrib['href'] + ']' + '\n'
                elif elem.tag == 'p':
                    s += elem.text + '\n'
                elif elem.tag == 'li':
                    s += '* '
                    if elem.text is not None:
                        s += elem.text + '\n'
                elif elem.text.isspace():
                    s += list(elem.itertext())[0]
                elif elem.tag == 'div' or elem.tag == 'span':
                    s += elem.text.strip() + '\n'
                else:
                    continue
            else:
                return s + self.get_content(elem)

        if s == '' and container.tag == 'div' and container.text is not None and len(container.text) > 0:
            if container.text[0] == '<':
                s += etree.tostring(container, encoding='unicode') + '\n'
            else:
                s += container.text.strip() + '\n'

        print('Returning :: ', s)
        return s

    def get_items(self, tree):
        # Check that there is at least one vulnerability (the vulnerabilities table is absent when no vuln are found)
        items = dict()
        severities = tree.xpath("/html/body/div/div[contains(@class, 'section')]/table[contains(@class, 'issue-table')]/tbody")
        
        sev_table = list(severities[0].iter("tr"))
        # for sev in sev_table:
        for item in range(0, len(sev_table), 2):
            title = list(sev_table[item].iter("td"))[0].text.strip()[:-4]
            severity = list(sev_table[item + 1].iter("td"))[1].text.strip()
            vuln = dict()
            vuln['Severity'] = severity
            vuln['Title'] = title
            vuln['Description'] = ''
            vuln['Impact'] = ''
            vuln['Mitigation'] = ''
            vuln['References'] = ''
            vuln['CWE'] = ''
            items[title] = vuln

        vulns = tree.xpath("/html/body/div/div[contains(@class, 'section details')]/div[contains(@class, 'issue-container')]")
        if(len(vulns) > 0):
            for issue in vulns:
                elems = list(issue.iterchildren())
                title = elems[1].text.strip()
                items[title]['Endpoint'] = elems[2].text.strip()
                description = ['Issue detail:', 'Issue description', 'Request:', 'Response:']

                for index in range(3, len(elems), 2):
                    primary, secondary = elems[index].text.strip(), elems[index + 1]

                    # print('pri')
                    # print(index, ' : tag  :: ', elems[index].tag)
                    # print(index, ' : text :: ', elems[index].text, '\n')
                    # if elems[index].text is not None and elems[index].text.strip() == '':
                    #     print(self.get_content(elems[index]))
                    # print('sec')
                    # print(index + 1, ' : tag  :: ', elems[index + 1].tag)
                    # print(index + 1, ' : text :: ', elems[index + 1].text, '\n')
                    # if elems[index + 1].text is not None and elems[index + 1].text.strip() == '':
                    #     print(self.get_content(elems[index + 1]))

                    # Description
                    if primary in description:
                        print('\"', primary, '\"')
                        print('sec')
                        print(index + 1, ' : tag  :: ', elems[index + 1].tag)
                        print(index + 1, ' : text :: ', elems[index + 1].text, '\n')
                        if elems[index + 1].text is not None and elems[index + 1].text.strip() == '':
                            print(self.get_content(elems[index + 1]))

                        print('************************************************')
                        s = str(items[title]['Description']) + str(self.get_content(secondary))
                        items[title]['Description'] = s
                    # Impact
                    if primary == 'Issue background':
                        items[title]['Impact'] = items[title]['Impact'] + self.get_content(secondary)
                    # Mitigation
                    if primary == 'Issue remediation':
                        items[title]['Mitigation'] = items[title]['Mitigation'] + self.get_content(secondary)
                    # References
                    if primary == 'References':
                        items[title]['References'] += items[title]['References'] + self.get_content(secondary)
                    # CWE
                    if primary == 'Vulnerability classifications':
                        items[title]['CWE'] += items[title]['CWE'] + self.get_content(secondary)

            print('Printing vulns\n\n')
            for k, v in items.items():
                for key, value in v.items():
                    print(key, ' :: ', value)
                print()

            raise Exception("Stop")
            self.create_findings(items)
            findings = list(self.dupes.values())
        else:
            findings = dict()
        return findings

    def get_cwe(self, vuln_references):
        # Match only the first CWE!
        cweSearch = re.search("CWE-([0-9]*)", vuln_references, re.IGNORECASE)
        if cweSearch:
            return cweSearch.group(1)
        else:
            return 0

    def create_findings(self, items):
        for title, details in items.items():
            cwe = self.get_cwe(details.get('CWE'))
            aggregateKeys = "{}{}{}".format(title, details.get('Description'), cwe)
            find = Finding(title=title,
                           description=details.get('Description'),
                           test=self.test,
                           severity=details.get('Severity'),
                           mitigation=details.get('Mitigation'),
                           references=details.get('References'),
                           impact=details.get('Impact'),
                           cwe=int(cwe),
                           active=False,
                           verified=False,
                           false_p=False,
                           duplicate=False,
                           out_of_scope=False,
                           mitigated=None,
                           numerical_severity=Finding.get_numerical_severity(details.get('Severity')),
                           static_finding=False,
                           dynamic_finding=True,
                           nb_occurences=1)
            self.dupes[aggregateKeys] = find
        return list(self.dupes.values())
            