__author__ = 'aaronweaver'

from defusedxml import ElementTree
from dateutil import parser
import ntpath
from dojo.utils import add_language

from dojo.models import Finding


class CheckmarxXMLParser(object):
    result_dupes = dict()
    language_list = []

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
            self.result_dupes = dict()
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
                if categories is not None:
                    findingdetail = "{}**Category:** {}\n".format(findingdetail, categories)

                if language is not None:
                    findingdetail = "{}**Language:** {}\n".format(findingdetail, language)
                    if language not in self.language_list:
                        self.language_list.append(language)

                if group is not None:
                    findingdetail = "{}**Group:** {}\n".format(findingdetail, group)

                if result.get('Status') is not None:
                    findingdetail = "{}**Status:** {}\n".format(findingdetail, result.get('Status'))

                deeplink = "[{}]({})".format(result.get('DeepLink'), result.get('DeepLink'))
                findingdetail = "{}**Finding Link:** {}\n\n".format(findingdetail, deeplink)

                dupe_key = "{}{}{}{}".format(categories, cwe, name, result.get('FileName'))

                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    title, description, pathnode = self.get_finding_detail(query, result)
                    "{}\n{}".format(find.description, description)
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
                                   file_path=pathnode.find('FileName').text,
                                   line=pathnode.find('Line').text,
                                   url='N/A',
                                   date=find_date,
                                   static_finding=True)
                    dupes[dupe_key] = find
                    findingdetail = ''

        for lang in self.language_list:
            add_language(test.engagement.product, lang)

        self.items = dupes.values()

    def get_finding_detail(self, query, result):
        findingdetail = ""
        title = ""

        for path in result.findall('Path'):
            title = query.get('name').replace('_', ' ')
            for pathnode in path.findall('PathNode'):
                result_dupes_key = pathnode.find('Line').text + "|" + pathnode.find('Column').text
                if result_dupes_key not in self.result_dupes:
                    findingdetail = "{}**Line Number:** {}\n".format(findingdetail, pathnode.find('Line').text)
                    findingdetail = "{}**Column:** {}\n".format(findingdetail, pathnode.find('Column').text)
                    findingdetail = "{}**Source Object:** {}\n".format(findingdetail, pathnode.find('Name').text)

                    for codefragment in pathnode.findall('Snippet/Line'):
                        findingdetail = "{}**Number:** {}\n**Code:** {}\n".format(findingdetail, codefragment.find('Number').text, codefragment.find('Code').text.strip())

                    findingdetail = '{}-----\n'.format(findingdetail)

                self.result_dupes[result_dupes_key] = True

        if title and pathnode.find('FileName').text:
            title = "{} ({})".format(title, ntpath.basename(pathnode.find('FileName').text))

        return title, findingdetail, pathnode
