__guide__ = 'aaronweaver'
__author__ = 'Rajarshi333'


from defusedxml import ElementTree
from dateutil import parser
import re
from dojo.models import Finding


class FortifyXMLParser(object):
    language_list = []

    def __init__(self, filename, test):
        Fortifyscan = ElementTree.parse(filename)
        root = Fortifyscan.getroot()

        # Get Date
        date_string = root.getchildren()[5].getchildren()[1].getchildren()[2].text
        date_list = date_string.split()[1:4]
        date_act = "".join(date_list)
        find_date = parser.parse(date_act)

        # Get Language
        lang_string = root[8][4][2].text
        lang_need_string = re.findall("^.*com.fortify.sca.Phase0HigherOrder.Languages.*$", lang_string, re.MULTILINE)
        lang_my_string = lang_need_string[0]
        language = lang_my_string.split('=')[1]
        if language not in self.language_list:
            self.language_list.append(language)

        # Get Finding Details
        dupes = dict()

        for ReportSection in root.findall('ReportSection'):
            if ReportSection.findtext('Title') == "Results Outline":
                kingdom = ''
                category = ''
                mitigation = 'N/A'
                impact = 'N/A'
                references = ''
                findingdetail = ''
                title = ''
                filename = ''
                filepath = ''
                linestart = ''
                dupe_key = ''
                filename = ''
                linestart = ''

            for GroupingSection in ReportSection.iter('GroupingSection'):
                for groupTitle in GroupingSection.iter('groupTitle'):
                    grouptitle = groupTitle.text
                cwe_id = grouptitle.split(' ')
                if len(cwe_id) > 2:
                    cwe_id = cwe_id[2]
                    if "," in cwe_id:
                        cwe_id = cwe_id[:1]
                else:
                    cwe_id = 0

                for Friority in GroupingSection.iter('Friority'):
                    sev = Friority.text

                for Category in GroupingSection.iter('Category'):
                    category = Category.text

                for Kingdom in GroupingSection.iter('Kingdom'):
                    kingdom = Kingdom.text

                for LineStart in GroupingSection.iter('LineStart'):
                    linestart = LineStart.text
                    if linestart is not None:
                        findingdetail += "**Line Start:**" + linestart + '\n'

                for Snippet in GroupingSection.iter('Snippet'):
                    snippet = Snippet.text
                    if snippet is not None:
                        findingdetail += "\n**Code:**\n'''\n" + snippet + "\n\n"

                    for FileName in GroupingSection.iter('FileName'):
                        filename = FileName.text
                        if filename is not None:
                            findingdetail += "**FileName:**" + filename + '\n'
                    for FilePath in GroupingSection.iter('FilePath'):
                        filepath = FilePath.text
                        if filepath is not None:
                            findingdetail += "**Filepath:**" + filepath + '\n'

                    title = category + " " + kingdom
                    dupe_key = (title + sev + cwe_id)

                    if dupe_key in dupes:
                        find = dupes[dupe_key]
                    else:
                        dupes[dupe_key] = True
                        find = Finding(title=title,
                                        cwe=cwe_id,
                                        test=test,
                                        active=False,
                                        verified=False,
                                        description=findingdetail,
                                        severity=sev,
                                        numerical_severity=Finding.get_numerical_severity(sev),
                                        mitigation=mitigation,
                                        impact=impact,
                                        references=references,
                                        file_path=filepath,
                                        line=linestart,
                                        url='N/A',
                                        date=find_date,
                                        static_finding=True)
                    dupes[dupe_key] = find
                    findingdetail = ''

        self.items = list(dupes.values())
