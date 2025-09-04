import hashlib
import json
from urllib.parse import urlparse
from dojo.models import Endpoint, Finding
from dojo.utils import parse_cvss_data
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
        for content in data.get('data', {}).get('auto', {}).get('assessment', {}).get('report', {}).get('findings', []):
            if  content.get('affected',[]):
                if content.get('check',{}).get('issue',[]):
                    # If the issue exist, it always has a title
                    title = content.get('check',{}).get('issue',{}).get('title',[])
                    for regulation in content.get('check',{}).get('issue',{}).get('regulations',[]):
                        if regulation.get('type',[]) == "cwe":
                            cwe = regulation.get('links',[])[0].get('title',[])
                    if content.get('check',{}).get('issue',{}).get('description',[]):
                        description = content.get('check',{}).get('issue',{}).get('description',[])
                    else:
                        description = ''''''
                    # https://docs.defectdojo.com/en/open_source/contributing/how-to-write-a-parser/#parsing-of-cvss-vectors
                    if content.get('check',{}).get('issue',{}).get('cvssVector',[]):
                        cvss_vector = content.get('check',{}).get('issue',{}).get('cvssVector',[])
                        cvss_data = parse_cvss_data(cvss_vector)
                        if cvss_data:
                            severity = cvss_data.get('severity',[]) 
                            cvssv3 = cvss_data.get('cvssv3',[])
                            cvssv4 = cvss_data.get('cvssv4',[])
                        # we don't set any score fields as those will be overwritten by Defect Dojo
                    if content.get('check',{}).get('issue',{}).get('recommendation',[]):
                        mitigation = content.get('check',{}).get('issue',{}).get('recommendation',[])
                        fix_available=True
                    else:
                        fix_available=False
                    
                    impact = content.get('check',{}).get('issue',{}).get('impactSummary',[]) or ''''''
                    if data.get('data',{}).get('auto',{}).get('assessment',{}).get('applicationRef',[]) and data.get('data',{}).get('auto',{}).get('assessment',{}).get('ref',[]) and content.get('checkId',[]):
                        url = f"https://app.nowsecure.com/app/{data.get('data',{}).get('auto',{}).get('assessment',{}).get('applicationRef',[])}/assessment/{data.get('data',{}).get('auto',{}).get('assessment',{}).get('ref',[])}?viewObservationsBy=categories&viewFindingsBy=policyCategory#{content.get('checkId',[])}"
                    steps_to_reproduce = (content.get('check',{}).get('issue',{}).get('stepsToReproduce',[]) or '''''')
                    if content.get('check',{}).get('issue',{}).get('codeSamples',[]):
                        code_samples = ''''''
                        for code_sample in content.get('check',{}).get('issue',{}).get('codeSamples',{}):
                            code_samples += f'''**{code_sample.get('platform',[])}**: {code_sample.get('caption',[])}\n```{code_sample.get('syntax',[])}\n{code_sample.get('block',[])}\n```\n'''
                        if code_samples:
                            steps_to_reproduce += code_samples
                    references = ''''''
                    if content.get('check',{}).get('issue',{}).get('guidanceLinks',[]):
                        references+="### Guidance Links\n"
                        for reference in content.get('check',{}).get('issue',{}).get('guidanceLinks',[]):
                            references+=f'''* [{reference.get('caption',[])}]({reference.get('url',[])})\n'''

                    cwe = None
                    if content.get('check',{}).get('issue',{}).get('regulations',[]):
                        references+="### Regulations\n"
                        for regulation in content.get('check',{}).get('issue',{}).get('regulations',{}):
                            if regulation.get('type',[]) == 'cwe':
                                cwe = regulation.get('links',[])[0].get('title',[])
                            for link in regulation.get('links',{}):
                                references+=f"* **{regulation.get('label',[])}**: [{link.get('title',[])}]({link.get('url',[])})\n"
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
                    cvssv4 = cvssv4,
                    mitigation = mitigation,
                    url = url,
                    steps_to_reproduce = steps_to_reproduce,
                    impact=impact,
                    references = references,
                    cwe = cwe,
                    cve = cve,
                    fix_available = fix_available,

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