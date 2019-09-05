__author__ = 'aaronweaver'

import logging

from defusedxml import ElementTree
from dateutil import parser
import ntpath
from dojo.utils import add_language

from dojo.models import Finding

logger = logging.getLogger(__name__)


class CheckmarxXMLParser(object):
    result_dupes = dict()
    language_list = []
    checkmarxAggregated = False

    # mode:
    # None (default): import all vunlerabilities from checkmarx
    # 'aggregated' : aggregates on sink filename, sink line number for each type of vunlnerability
    def __init__(self, filename, test, mode=None):
        cxscan = ElementTree.parse(filename)
        root = cxscan.getroot()

        if(mode == "aggregated"):
            self.checkmarxAggregated = True

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

                if(self.checkmarxAggregated):
                    dupe_key = "{}{}{}{}".format(categories, cwe, name, result.get('FileName').encode('utf-8'))

                    if dupe_key in dupes:
                        # Those 4 lines aren't doing anything??
                        find = dupes[dupe_key]
                        title, description, pathnode = self.get_finding_detail_aggregated(query, result)
                        "{}\n{}".format(find.description, description)
                        dupes[dupe_key] = find
                    else:
                        dupes[dupe_key] = True

                        sev = result.get('Severity')
                        result.get('FileName')
                        title, description, pathnode = self.get_finding_detail_aggregated(query, result)
                        find = Finding(title=title,
                                       cwe=int(cwe),
                                       test=test,
                                       active=False,
                                       verified=False,
                                       description=findingdetail + '-----\n' + description,
                                       severity=sev,
                                       numerical_severity=Finding.get_numerical_severity(sev),
                                       mitigation=mitigation,
                                       impact=impact,
                                       references=references,
                                       # this is not the same as in the dupe_key
                                       file_path=pathnode.find('FileName').text,
                                       line=pathnode.find('Line').text,
                                       url='N/A',
                                       date=find_date,
                                       static_finding=True)
                        dupes[dupe_key] = find
                        findingdetail = ''
                else:
                    dupe_key = "{}{}{}{}".format(categories, cwe, name, result.get('FileName').encode('utf-8'))
                    sev = result.get('Severity')
                    # Get directly the filename from Result tag, whereas aggregated mode was fetching it from the last pathNode under the first path
                    # filename = result.find('FileName').text
                    # Get directly the line from Result tag (it is the source line), whereas aggregated mode was fetching the sink line from the last pathNode under the first path
                    # This is more coherent with the information we have in checkmarx
                    # lineNumber = result.find('Line').text
                    # title = query name + filename
                    title = query.get('name').replace('_', ' ')
                    # Loop over findings
                    for path in result.findall('Path'):
                        sourceFilename = ''
                        sinkFilename = ''
                        sourceLineNumber = None
                        sinkLineNumber = None
                        sourceObject = ''
                        sinkObject = ''
                        pathId = path.get('PathId')
                        findingdetail = '{}-----\n'.format(findingdetail)
                        # Loop over function calls / assignments in the data flow graph
                        for pathnode in path.findall('PathNode'):
                            findingdetail = self.get_description(pathnode, findingdetail)
                            nodeId = pathnode.find('NodeId').text
                            if(nodeId == "1"):
                                sourceFilename = pathnode.find('FileName').text
                                sourceLineNumber = pathnode.find('Line').text
                                sourceObject = pathnode.find('Name').text
                        # the last pathnode is the sink
                        sinkFilename = pathnode.find('FileName').text
                        sinkLineNumber = pathnode.find('Line').text
                        sinkObject = pathnode.find('Name').text
                        dupe_key = "{}{}{}{}{}".format(categories, cwe, name, sinkFilename, pathId)
                        if title and sinkFilename:
                            title = "{} ({})".format(title, ntpath.basename(sinkFilename))

                        find = Finding(title=title,
                                   cwe=int(cwe),
                                   test=test,
                                   active=False,
                                   verified=False,
                                   description=findingdetail,
                                   severity=sev,
                                   numerical_severity=Finding.get_numerical_severity(sev),
                                   mitigation=mitigation,
                                   impact=impact,
                                   references=references,
                                   file_path=sinkFilename,
                                   line=sinkLineNumber,
                                   url='N/A',
                                   date=find_date,
                                   static_finding=True,
                                   unique_id_from_tool=pathId,
                                   sast_source_object=sourceObject,
                                   sast_sink_object=sinkObject,
                                   sast_source_line=sourceLineNumber,
                                   sast_source_file_path=sourceFilename)
                    dupes[dupe_key] = find
                    findingdetail = ''
        for lang in self.language_list:
            add_language(test.engagement.product, lang)

        self.items = list(dupes.values())

    def get_finding_detail_aggregated(self, query, result):
        findingdetail = ""
        title = ""

        for path in result.findall('Path'):
            title = query.get('name').replace('_', ' ')
            for pathnode in path.findall('PathNode'):
                result_dupes_key = pathnode.find('Line').text + "|" + pathnode.find('Column').text
                if result_dupes_key not in self.result_dupes:
                    findingdetail = self.get_description(pathnode, findingdetail)
                self.result_dupes[result_dupes_key] = True

        # At this point we have iterated over all paths and pathnode is at the sink of the vulnerability
        if title and pathnode.find('FileName').text:
            title = "{} ({})".format(title, ntpath.basename(pathnode.find('FileName').text))
        return title, findingdetail, pathnode

    def get_description(self, pathnode, findingdetail):
        if pathnode.find('Line').text is not None:
            findingdetail = "{}**Line Number:** {}\n".format(findingdetail, pathnode.find('Line').text)

        if pathnode.find('Column').text is not None:
            findingdetail = "{}**Column:** {}\n".format(findingdetail, pathnode.find('Column').text)

        if pathnode.find('Name').text is not None:
            findingdetail = "{}**Source Object:** {}\n".format(findingdetail, pathnode.find('Name').text)

        for codefragment in pathnode.findall('Snippet/Line'):
            findingdetail = "{}**Number:** {}\n**Code:** {}\n".format(findingdetail, codefragment.find('Number').text, codefragment.find('Code').text.strip())

        findingdetail = '{}-----\n'.format(findingdetail)
        return findingdetail

#        def setTitle(self, title, pathnode):
#            if title and pathnode.find('FileName').text:
#                return "{} ({})".format(title, ntpath.basename(pathnode.find('FileName').text))
