# import hashlib
# import json
# from urllib.parse import urlparse
# from dojo.models import Endpoint, Finding


# class NowSecureParser(object):
#     """
#     testing apps that touch your enterprise, preventing data leakage or unauthorized access.
#     """

#     def get_scan_types(self):
#         return ["NowSecure Scan"]

#     def get_label_for_scan_types(self, scan_type):
#         return "NowSecure Scan"

#     def get_description_for_scan_types(self, scan_type):
#         return "NowSecure report file can be imported in JSON format (option --json)."

#     def get_findings(self, file, test):
#         data = json.load(file)

#         dupes = dict()
#         for content in tree:
#             node = tree[content]
#             if not node['pass']:
#                 title = node['name']
#                 description = "**Score Description** : " + node['score_description'] + "\n\n" + \
#                             "**Result** : " + node['result'] + "\n\n" + \
#                             "**expectation** : " + node['expectation'] + "\n"
#                 severity = self.get_severity(int(node['score_modifier']))
#                 output = node['output']
#                 try:
#                     url = output['destination']
#                     parsedUrl = urlparse(url)
#                     protocol = parsedUrl.scheme
#                     query = parsedUrl.query
#                     fragment = parsedUrl.fragment
#                     path = parsedUrl.path
#                     port = ""
#                     try:
#                         host, port = parsedUrl.netloc.split(':')
#                     except:
#                         host = parsedUrl.netloc
#                 except:
#                     url = None

#                 finding = Finding(
#                     title=title,
#                     test=test,
#                     description=description,
#                     severity=severity,

#                     static_finding=True,
#                     dynamic_finding=False, 
# )

#                 # some attribute are optional
#                 if 'mitigationFromTheTool' in node:
#                     finding.mitigation = node['mitigationFromTheTool']

#                 # take a look at all the attributes possible in the documentation
#                 # some are very usefull like
#                 #  - date (DATE / date when the finding was detected)
#                 #  - component_name (STRING / if the finding is liked to an external component ex: 'log4j')
#                 #  - component_version (STRING / if the finding is liked to an external component ex: '1.2.13')
#                 #  - file_path (STRING / if the finding is liked to a specfic file ex: 'src/foo.c')
#                 #  - line (INTEGER / if the finding is liked to an specific file ex: 23)

#                 # manage endpoint
#                 finding.unsaved_endpoints = list()
#                 if url is not None:
#                     finding.unsaved_endpoints.append(Endpoint(
#                             host=host, port=port,
#                             path=path,
#                             protocol=protocol,
#                             query=query, fragment=fragment))

#                 # internal de-duplication
#                 dupe_key = hashlib.sha256(str(description + title).encode('utf-8')).hexdigest()
#                 if dupe_key in dupes:
#                     find = dupes[dupe_key]
#                     if finding.description:
#                         find.description += "\n" + finding.description
#                     find.unsaved_endpoints.extend(finding.unsaved_endpoints)
#                     dupes[dupe_key] = find
#                 else:
#                     dupes[dupe_key] = finding

#         return list(dupes.values())

#     def convert_severity(self, num_severity):
#         """Convert severity value"""
#         if num_severity >= -10:
#             return "Low"
#         elif -11 >= num_severity > -26:
#             return "Medium"
#         elif num_severity <= -26:
#             return "High"
#         else:
#             return "Info"
import hashlib
import json
from urllib.parse import urlparse
from dojo.models import Endpoint, Finding
import re

class NowSecureParser(object):
    """
    Importing findings from NowSecure app analysis.
    """

    def get_scan_types(self):
        return ["NowSecure Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "NowSecure Scan"

    def get_description_for_scan_types(self, scan_type):
        return "NowSecure report file can be imported in JSON format (option --json)."

    def get_findings(self, file, test):
        data = json.load(file)

        dupes = dict()
        for content in data['data']['auto']['assessment']['report']['findings']:
            if  content['affected']:
                if content['check']['issue']:
                    title = content['check']['issue']['title']
                    for regulation in content['check']['issue']['regulations']:
                        if regulation['type'] == "cwe":
                            cwe = regulation['links'][0]['title']
                    description = content['check']['issue']['description']
                    severity = content['check']['issue']['severity'].capitalize()
                    cvssv3 = content['check']['issue']['cvssVector']
                    cvssv3_score = content['check']['issue']['cvss']
                    mitigation = content['check']['issue']['recommendation']
                    impact = content['check']['issue']['impactSummary']
                    url = f"https://app.nowsecure.com/app/{data['data']['auto']['assessment']['applicationRef']}/assessment/{data['data']['auto']['assessment']['ref']}?viewObservationsBy=categories&viewFindingsBy=policyCategory#{content['checkId']}"
                    steps_to_reproduce = (content['check']['issue']['stepsToReproduce'] or '''''')
                    if content['check']['issue']['codeSamples']:
                        code_samples = ''''''
                        for code_sample in content['check']['issue']['codeSamples']:
                            code_samples += f'''**{code_sample['platform']}**: {code_sample['caption']}\n```{code_sample['syntax']}\n{code_sample['block']}\n```\n'''
                        if code_samples:
                            steps_to_reproduce += code_samples
                    references = ''''''
                    if content['check']['issue']['guidanceLinks']:
                        references+="### Guidance Links\n"
                        for reference in content['check']['issue']['guidanceLinks']:
                            references+=f'''* [{reference['caption']}]({reference['url']})\n'''

                    cwe = None
                    if content['check']['issue']['regulations']:
                        references+="### Regulations\n"
                        for regulation in content['check']['issue']['regulations']:
                            if regulation['type'] == 'cwe':
                                cwe = regulation['links'][0]['title']
                            for link in regulation['links']:
                                references+=f"* **{regulation['label']}**: [{link['title']}]({link['url']})\n"
                    cve = None
                    cve_pattern = r'CVE-\d{4}-\d{4,7}'
                    cve_matches = re.findall(cve_pattern, title)
                    if cve_matches:
                        cve = list(dict.fromkeys(cve_matches))[0]
                    
                finding = Finding(
                    title=title,
                    test=test,
                    description=description,
                    severity=severity,
                    cvssv3 = cvssv3,
                    cvssv3_score = cvssv3_score,
                    mitigation = mitigation,
                    url = url,
                    steps_to_reproduce = steps_to_reproduce,
                    impact=impact,
                    references = references,
                    cwe = cwe,
                    cve = cve,

                    static_finding=True,
                    dynamic_finding=False, 
)
                dupe_key = hashlib.sha256(str(description + title).encode('utf-8')).hexdigest()
                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    if finding.description:
                        find.description += "\n" + finding.description
                    find.unsaved_endpoints.extend(finding.unsaved_endpoints)
                    dupes[dupe_key] = find
                else:
                    dupes[dupe_key] = finding

        return list(dupes.values())

    def convert_severity(self, num_severity):
        """Convert severity value"""
        if num_severity >= -10:
            return "Low"
        elif -11 >= num_severity > -26:
            return "Medium"
        elif num_severity <= -26:
            return "High"
        else:
            return "Info"