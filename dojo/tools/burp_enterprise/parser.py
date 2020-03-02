from lxml import etree
from dojo.models import Endpoint, Finding
import logging
import re
from urllib.parse import urlparse


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
        s = ''
        if container.tag == 'div' and container.text is not None and not container.text.isspace() and len(container.text) > 0:
            s += ''.join(container.itertext()).strip().replace('Snip', '<-------------- Snip -------------->').replace('\t', '')
        else:
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
                    s += self.get_content(elem)
        return s

    def get_items(self, tree):
        # Check that there is at least one vulnerability (the vulnerabilities table is absent when no vuln are found)
        items = list()
        endpoint_text = tree.xpath("/html/body/div/div[contains(@class, 'section')]/h1")
        severities = tree.xpath("/html/body/div/div[contains(@class, 'section')]/table[contains(@class, 'issue-table')]/tbody")
        endpoint_text = [endpoint for endpoint in endpoint_text if ('Issues found' in ''.join(endpoint.itertext()).strip())]
        # print('num endpoints :: ', len(endpoint_text))
        # for container in endpoint_text:
        #     print(''.join(container.itertext()).strip())
        # print('num severities :: ', len(severities))
        # for container in severities:
        #     print('Count')
        #     print(''.join(container.itertext()).strip())

        for index in range(0, len(severities)):
            url = endpoint_text[index].text[16:]
            sev_table = list(severities[index].iter("tr"))
            # print('url :: ', url)
            # print('table size :: ', len(sev_table))
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
                vuln['Endpoint'] = url
                items.append(vuln)

        vulns = tree.xpath("/html/body/div/div[contains(@class, 'section details')]/div[contains(@class, 'issue-container')]")
        if(len(vulns) > 0):
            dict_index = 0
            description = ['Issue detail:', 'Issue description', 'Request:', 'Response:']
            for issue in vulns:
                elems = list(issue.iterchildren())
                vuln = items[dict_index]
                vuln['Endpoint'] = vuln['Endpoint'] + elems[2].text.strip()

                for index in range(3, len(elems), 2):
                    primary, secondary = elems[index].text.strip(), elems[index + 1]
                    # Description
                    if primary in description:
                        s = self.get_content(secondary)
                        if primary == 'Request:' or primary == 'Response:':
                            s = '\n\n' + primary + '\n' + s
                        vuln['Description'] = vuln['Description'] + s
                    # Impact
                    if primary == 'Issue background':
                        vuln['Impact'] = vuln['Impact'] + self.get_content(secondary)
                    # Mitigation
                    if primary == 'Issue remediation':
                        vuln['Mitigation'] = vuln['Mitigation'] + self.get_content(secondary)
                    # References
                    if primary == 'References':
                        vuln['References'] = vuln['References'] + self.get_content(secondary)
                    # CWE
                    if primary == 'Vulnerability classifications':
                        s = self.get_content(secondary)
                        if len(vuln['CWE']) < 1:
                            vuln['CWE'] += vuln['CWE'] + s
                        vuln['References'] = vuln['References'] + s

                dict_index += 1

            # print('Printing vulns\n\n')
            # for v in items:
            #     for key, value in v.items():
            #         # print(key, ' :: ', value)
            #         if key == 'Endpoint':
            #             url = value
            #             parsedUrl = urlparse(url)
            #             protocol = parsedUrl.scheme
            #             query = parsedUrl.query
            #             fragment = parsedUrl.fragment
            #             path = parsedUrl.path
            #             port = ""  # Set port to empty string by default
            #             # Split the returned network address into host and
            #             try:  # If there is port number attached to host address
            #                 host, port = parsedUrl.netloc.split(':')
            #             except:  # there's no port attached to address
            #                 host = parsedUrl.netloc

            #             print('host :: ', host)
            #             print('port :: ', port)
            #             print('path :: ', path)
            #             print('protocol :: ', protocol)
            #             print('query :: ', query)
            #             print('fragment :: ', fragment)
            #     print()

            # raise Exception("stop")

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
        for details in items:
            cwe = self.get_cwe(details.get('CWE'))
            aggregateKeys = "{}{}{}{}".format(details.get('Title'), details.get('Description'), cwe, details.get('Endpoint'))
            find = Finding(title=details.get('Title'),
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

            url = details.get('Endpoint')
            parsedUrl = urlparse(url)
            protocol = parsedUrl.scheme
            query = parsedUrl.query
            fragment = parsedUrl.fragment
            path = parsedUrl.path
            port = ""  # Set port to empty string by default
            # Split the returned network address into host and
            try:  # If there is port number attached to host address
                host, port = parsedUrl.netloc.split(':')
            except:  # there's no port attached to address
                host = parsedUrl.netloc

            find.unsaved_endpoints = list()
            self.dupes[aggregateKeys] = find

            find.unsaved_endpoints.append(Endpoint(
                    host=host, port=port,
                    path=path,
                    protocol=protocol,
                    query=query, fragment=fragment))

        return list(self.dupes.values())
