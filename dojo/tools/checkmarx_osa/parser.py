import json
import logging
from dojo.models import Finding
from datetime import datetime

logger = logging.getLogger(__name__)


class CheckmarxOsaParser(object):

    def get_scan_types(self):
        return ["Checkmarx OSA"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Checkmarx Open Source Analysis for dependencies (json). Generate with `jq -s . CxOSAVulnerabilities.json CxOSALibraries.json`"

    def get_findings(self, filehandle, test):
        tree = json.load(filehandle)
        if len(tree) != 2:
            logger.error("Bad format. Expected a list of two elements: CxOSALibraries.json and CxOSAVulnerabilities.json. Found %i elements", len(tree))
            raise Exception("Invalid format: bad structure")
        libraries_dict = self.get_libraries(tree)
        vulnerabilities = self.get_vunlerabilities(tree)
        items = []
        for item in vulnerabilities:
            library = libraries_dict[item['libraryId']]
            # Possible status as per checkmarx 9.2: TO_VERIFY, NOT_EXPLOITABLE, CONFIRMED, URGENT, PROPOSED_NOT_EXPLOITABLE
            status = item['state']['name']
            finding_item = Finding(
                title='{0} {1} | {2}'.format(library['name'], library['version'], item['cveName']),
                severity=item['severity']['name'],
                description=item['description'],
                unique_id_from_tool=item['id'],
                references=self.safe_use_str(item, 'url'),
                mitigation=self.safe_use_str(item, 'recommendations'),
                impact='NC',
                component_name=library['name'],
                component_version=library['version'],
                cve=item['cveName'],
                # 1035 is "Using Components with Known Vulnerabilities"
                # Possible improvment: get the CWE from the CVE using some database?
                # nvd.nist.gov has the info; see for eg https://nvd.nist.gov/vuln/detail/CVE-2020-25649 "Weakness Enumeration"
                cwe=1035,
                cvssv3_score=self.safe_use_score(item, 'score', item['cveName']),
                publish_date=datetime.strptime(item['publishDate'], '%Y-%m-%dT%H:%M:%S'),
                static_finding=True,
                dynamic_finding=False,
                scanner_confidence=self.checkmarx_confidence_to_defectdojo_confidence(library['confidenceLevel']),
                active=status != 'NOT_EXPLOITABLE',
                false_p=status == 'NOT_EXPLOITABLE',
                verified=status != 'TO_VERIFY' and status != 'NOT_EXPLOITABLE' and status != 'PROPOSED_NOT_EXPLOITABLE',
                test=test
            )
            items.append(finding_item)
        return items

    def get_libraries(self, tree):
        libraries_dict = {}
        for library in tree[1]:
            libraries_dict[library['id']] = library
        return libraries_dict

    def get_vunlerabilities(self, tree):
        return tree[0]

    # Translate checkmarx quotation of confidence to defectdojo one
    # Checkmarx: ref https://checkmarx.atlassian.net/wiki/spaces/CCOD/pages/968622682/Generating+a+CxOSA+Scan+Results+Report
    #   "Filename Match - with confidence level 70%'
    #   "Exact Match - with confidence level 100%"
    #    -> checkmarx has a quotation from 0->100 with 100 highest confidence

    # Defectdojo: cf models.py get_scanner_confidence_text
    #   1->2 = Certain (0 is like null)
    #   3->5 = Firm
    #   >=6 : Tentative 
    #   -> defectdojo has a quotation from 1->(say)11 with 1 the highest confidence

    # 100% = Certain
    # 70% = Firm
    def checkmarx_confidence_to_defectdojo_confidence(self, checkmarx_confidence):
        return round((100 - checkmarx_confidence) / 10) + 1

    def safe_use_str(self, item, key):
        return item[key] if key in item else ""

    # Default to the max score so that we notice if it ever happens that we don't have a score
    def safe_use_score(self, item, key, cve):
        if key in item:
            return item[key]
        else:
            logger.error("Can't find cvssv3 score for finding of cve %s. Defaulting to maximum score", cve)
            return 10.0
