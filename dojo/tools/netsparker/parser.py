import json
import re
from dojo.models import Finding, Endpoint, Endpoint_Params

__author__ = "Roy Shoemake"
__status__ = "Development"


# Function to remove HTML tags
TAG_RE = re.compile(r'<[^>]+>')


def cleantags(text):
    # Added type-cast here, kept getting a TypeError on this function
    return TAG_RE.sub('', str(text))


class NetsparkerParser(object):
    def __init__(self, filename, test):
        tree = filename.read()
        try:
            data = json.loads(str(tree, 'utf-8'))
        except:
            data = json.loads(tree)
        dupes = dict()
        finding_list = dict()

        for item in data["Vulnerabilities"]:
            categories = ''
            language = ''
            mitigation = ''
            impact = ''
            references = ''
            findingdetail = ''
            title = ''
            group = ''
            status = ''
            # Added
            steps_to_reproduce = ''
            unsaved_endpoints = list()
            severity_justification = ''

            title = item["Name"]
            # moved url up here
            url = item["Url"]
            endpoint_url = Endpoint(host=url)
            # Putting the full HTTP request and response in the "Steps to Reproduce"
            steps_to_reproduce = "HTTP Request: \n\n" + item["HttpRequest"]["Content"] + "\n\nHTTP Response: \n\n" + \
                                 item["HttpResponse"]["Content"]
            # Put the URL in the Description
            findingdetail = cleantags(item["Description"])
            # Adding any "Extra Information" in the JSON to the justification field
            if len(item["ExtraInformation"]) > 0:
                for info in item["ExtraInformation"]:
                    severity_justification += info["Name"] + ": " + info["Value"] + "\n\n"
            # Added try-catch for Vulnerabilites with no Cwe in JSON
            try:
                cwe = item["Classification"]["Cwe"]
            except:
                cwe = '0'
            sev = item["Severity"]
            if sev not in ['Info', 'Low', 'Medium', 'High', 'Critical']:
                sev = 'Info'
            mitigation = cleantags(item["RemedialProcedure"])
            # Added to handle null references in JSON
            if item["RemedyReferences"]:
                # Removed the cleartags call, need to understand if this affects other things
                references = item["RemedyReferences"]
            impact = cleantags(item["Impact"])
            dupe_key = title + item["Name"] + item["Url"]
            # Added the finding_list to hold the multi-endpoint findings
            finding_list_key = title + item["Name"]

            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                if finding_list_key in finding_list:
                    finding_list[finding_list_key].unsaved_endpoints.append(endpoint_url)
                    # This will add the HTTP req/resp for each endpoint
                    # finding_list[finding_list_key].steps_to_reproduce += "\n\nFor Endpoint: " + url + "\n" + \
                    #                                                     steps_to_reproduce
                else:
                    dupes[dupe_key] = True

                    find = Finding(title=title,
                                   test=test,
                                   active=False,
                                   verified=False,
                                   description=findingdetail,
                                   severity=sev.title(),
                                   numerical_severity=Finding.get_numerical_severity(sev),
                                   # Added the HTTP request to step to reproduce
                                   steps_to_reproduce="For Endpoint: " + url + "\n\n" + steps_to_reproduce,
                                   mitigation=mitigation,
                                   impact=impact,
                                   references=references,
                                   severity_justification=severity_justification,
                                   url=url,
                                   cwe=cwe,
                                   # Changed to False
                                   static_finding=False)
                    # Added the URL from the scan as an unsaved endpoint
                    find.unsaved_endpoints = list()
                    find.unsaved_endpoints.append(endpoint_url)
                    dupes[dupe_key] = find
                    finding_list[finding_list_key] = find
                    findingdetail = ''

        self.items = list(finding_list.values())
