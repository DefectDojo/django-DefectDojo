from xml.dom import NamespaceErr
import StringIO
import hashlib
import re
from defusedxml import ElementTree as ET
from dojo.models import Endpoint, Finding

__author__ = 'dr3dd589'

class OpenscapXMLParser(object):
    def __init__(self, file, test):
        self.dupes = dict()
        self.items = ()
        if file is None:
            return

        tree = ET.parse(file)
        root = tree.getroot()
        namespace = self.get_namespace(root)
        test_result = tree.find('./{0}TestResult'.format(namespace))

        if 'Benchmark' not in root.tag:
            raise NamespaceErr("This doesn't seem to be a valid Openscap vulnerability scan xml file.")
        
        for rule, rule_result in zip(root.findall('./{0}Rule'.format(namespace)), test_result.findall('./{0}rule-result'.format(namespace))):
            cves = []
            result = rule_result.find('./{0}result'.format(namespace)).text
            if "fail" in result:
                title = rule.find('./{0}title'.format(namespace)).text
                description = "**Title** : " + title + "\n\n"
                mitigation = "N/A"
                impact = "N/A"
                for cve in rule_result.findall('./{0}ident'.format(namespace)):
                    cves.append(cve.text)
                
                if len(cves) > 1:
                    cve_desc = ""
                    for cve in cves:
                        cve_desc += '[{0}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={0})'.format(cve) + ", "

                    description += "**Releted CVE's** : " + cve_desc[:-2]
                else:
                    cve = cves[0]
                
                severity = rule_result.attrib['severity'].lower().capitalize()
                check_content = rule_result.find('./{0}check/{0}check-content-ref'.format(namespace)).attrib
                references = "**name** : " + check_content['name'] + "\n" + \
                            "**href** : " + check_content['href'] + "\n"
            
                print(severity)
                dupe_key = hashlib.md5(references).hexdigest()

                if dupe_key in self.dupes:
                    finding = self.dupes[dupe_key]
                    if finding.references:
                        finding.references = finding.references
                    # self.process_endpoints(finding, ip)
                    self.dupes[dupe_key] = finding
                else:
                    self.dupes[dupe_key] = True

                    finding = Finding(title=title,
                                    test=test,
                                    active=False,
                                    verified=False,
                                    cve=cve,
                                    description=description,
                                    severity=severity,
                                    numerical_severity=Finding.get_numerical_severity(
                                        severity),
                                    mitigation=mitigation,
                                    impact=impact,
                                    references=references,
                                    url='N/A',
                                    dynamic_finding=True)

                    self.dupes[dupe_key] = finding
                    # self.process_endpoints(finding, ip)

            self.items = self.dupes.values()
    
    def get_namespace(self, element):
        m = re.match('\{.*\}', element.tag)
        return m.group(0) if m else ''