import hashlib
import json
from urllib.parse import urlparse
from dojo.models import Endpoint, Finding


class PopeyeParserParser(object):
    """
    kubernetes clusters scanning
    """

    def get_scan_types(self):
        return ["popeye Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "popeye Scan"

    def get_description_for_scan_types(self, scan_type):
        return "popeye report file can be imported in JSON format (option --json)."

    def get_findings(self, file, test):
        data = json.load(file)

        dupes = dict()
        for content in tree:
            node = tree[content]
            if not node['pass']:
                title = node['name']
                description = "**Score Description** : " + node['score_description'] + "\n\n" + \
                            "**Result** : " + node['result'] + "\n\n" + \
                            "**expectation** : " + node['expectation'] + "\n"
                severity = self.get_severity(int(node['score_modifier']))
                output = node['output']
                try:
                    url = output['destination']
                    parsedUrl = urlparse(url)
                    protocol = parsedUrl.scheme
                    query = parsedUrl.query
                    fragment = parsedUrl.fragment
                    path = parsedUrl.path
                    port = ""
                    try:
                        host, port = parsedUrl.netloc.split(':')
                    except:
                        host = parsedUrl.netloc
                except:
                    url = None

                finding = Finding(
                    title=title,
                    test=test,
                    description=description,
                    severity=severity,

                    static_finding=True,
                    dynamic_finding=False, 
)

                # some attribute are optional
                if 'mitigationFromTheTool' in node:
                    finding.mitigation = node['mitigationFromTheTool']

                # take a look at all the attributes possible in the documentation
                # some are very usefull like
                #  - date (DATE / date when the finding was detected)
                #  - component_name (STRING / if the finding is liked to an external component ex: 'log4j')
                #  - component_version (STRING / if the finding is liked to an external component ex: '1.2.13')
                #  - file_path (STRING / if the finding is liked to a specfic file ex: 'src/foo.c')
                #  - line (INTEGER / if the finding is liked to an specific file ex: 23)

                # manage endpoint
                finding.unsaved_endpoints = list()
                if url is not None:
                    finding.unsaved_endpoints.append(Endpoint(
                            host=host, port=port,
                            path=path,
                            protocol=protocol,
                            query=query, fragment=fragment))

                # internal de-duplication
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
