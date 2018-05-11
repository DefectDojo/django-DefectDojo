__author__ = 'aaronweaver'

from defusedxml import ElementTree
from datetime import datetime
from dateutil import parser
import ntpath

from dojo.models import Finding


class CheckmarxXMLParser(object):
    def __init__(self, filename, test):
        cxscan = ElementTree.parse(filename)
        root = cxscan.getroot()

        dupes = dict()

        for query in root.findall('Query'):
            categories = ''
            language = ''
            mitigation = 'N/A'
            impact = 'N/A'
            references = ''
            findingdetail = ''
            title = ''
            group = ''
            status = ''

            find_date = parser.parse(root.get("ScanStart"))
            name = query.get('name')
            cwe = query.get('cweId')

            if query.get('categories') is not None:
                categories = query.get('categories')

            if query.get('Language') is not None:
                language = query.get('Language')

            if query.get('group') is not None:
                group = query.get('group').replace('_', ' ')

            for result in query.findall('Result'):
                deeplink = result.get('DeepLink')

                if categories is not None:
                    findingdetail = 'Category: ' +  categories + '\n'

                if language is not None:
                    findingdetail += 'Language: ' +  language + '\n'

                if group is not None:
                    findingdetail += 'Group: ' +  group + '\n'

                if result.get('Status') is not None:
                    findingdetail += 'Status: ' +  result.get('Status') + '\n'

                findingdetail += 'Finding Link: ' +  deeplink + '\n\n'

                dupe_key = categories + cwe + name + result.get('FileName')   # + result.get('Line')

                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    title, description, pathnode = self.get_finding_detail(query, result)
                    find.description = find.description + "\n" + description
                    dupes[dupe_key] = find
                else:
                    dupes[dupe_key] = True

                    sev = result.get('Severity')
                    result.get('FileName')
                    title, description, pathnode = self.get_finding_detail(query, result)

                    find = Finding(title=title,
                                   cwe=int(cwe),
                                   test=test,
                                   active=False,
                                   verified=False,
                                   description=findingdetail + description,
                                   severity=sev,
                                   numerical_severity=Finding.get_numerical_severity(sev),
                                   mitigation=mitigation,
                                   impact=impact,
                                   references=references,
                                   file_path = pathnode.find('FileName').text,
                                   line = pathnode.find('Line').text,
                                   url='N/A',
                                   date=find_date,
                                   static_finding=True)
                    dupes[dupe_key] = find
                    findingdetail = ''

        self.items = dupes.values()

    def get_finding_detail(self, query, result):
        findingdetail = ""
        title = ""

        for path in result.findall('Path'):
            title = query.get('name').replace('_', ' ')  # + ' (' + path.get('PathId') + ')'
            for pathnode in path.findall('PathNode'):
                findingdetail += 'Source Object: %s\n' % (pathnode.find('Name').text)

                for codefragment in pathnode.findall('Snippet/Line'):
                    findingdetail += 'Code: %s\n' % (codefragment.find('Code').text.strip())

                findingdetail += '\n'

        if pathnode:
            findingdetail = "Line Number: " + pathnode.find('Line').text + "\n" + findingdetail

        if title and pathnode.find('FileName').text:
            title = title + " (" + ntpath.basename(pathnode.find('FileName').text) + ")"

        return title, findingdetail, pathnode
