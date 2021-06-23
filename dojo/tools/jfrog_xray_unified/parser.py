import json
from datetime import datetime

from dojo.models import Finding


class JFrogXrayUnifiedParser(object):
    """JFrog Xray JSON reports"""

    def get_scan_types(self):
        return ["JFrog Xray Unified Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Xray Unified (i.e. Xray version 3+) findings in JSON format."

    def get_findings(self, json_output, test):
        tree = json.load(json_output)
        return self.get_items(tree, test)

    def get_items(self, tree, test):
        items = []
        if 'rows' in tree:
            vulnerabilityTree = tree['rows']

            for node in vulnerabilityTree:
                item = get_item(node, test)

                items.append(item)

        return items


def get_item(vulnerability, test):
    # Some items have multiple CVEs for some reason, so get the CVE with the highest CVSSv3 score.
    # Note: the xray v2 importer just took the first CVE in the list, that doesn't seem ideal though
    highestCvssV3Index = 0
    highestCvssV3Score = 0

    for thisCveIndex in range(0, len(vulnerability['cves']) - 1):
        # not all cves have cvssv3 scores, so skip these. If no v3 scores, we'll default to index 0
        if 'cvss_v3_score' in vulnerability['cves'][thisCveIndex]:
            thisCvssV3Score = vulnerability['cves'][thisCveIndex]['cvss_v3_score']
            if thisCvssV3Score > highestCvssV3Score:
                highestCvssV3Index = thisCveIndex
                highestCvssV3Score = thisCvssV3Score

    # Following the CVSS Scoring per https://nvd.nist.gov/vuln-metrics/cvss
    if 'severity' in vulnerability:
        if vulnerability['severity'] == 'Unknown':
            severity = "Info"
        else:
            severity = vulnerability['severity'].title()
    # TODO: Needs UNKNOWN new status in the model.
    else:
        severity = "Info"

    cveIndex = highestCvssV3Index

    cve = None
    cvss_v3 = "No CVSS v3 score."  # for justification field
    cvssv3 = None  # for actual cvssv3 field
    cvss_v2 = "No CVSS v2 score."
    mitigation = None
    extra_desc = ""

    cves = vulnerability.get('cves', [])
    if len(cves) > 0:
        worstCve = cves[cveIndex]
        if 'cve' in cves[cveIndex]:
            cve = worstCve['cve']
        if 'cvss_v3_vector' in worstCve:
            cvss_v3 = worstCve['cvss_v3_vector']
            cvssv3 = cvss_v3
        if 'cvss_v2_vector' in worstCve:
            cvss_v2 = worstCve['cvss_v2_vector']

    if 'fixed_versions' in vulnerability and len(vulnerability['fixed_versions']) > 0:
        mitigation = "Versions containing a fix:\n"
        mitigation = mitigation + "\n".join(vulnerability['fixed_versions'])

    if 'external_advisory_source' in vulnerability and 'external_advisory_severity' in vulnerability:
        extra_desc = vulnerability['external_advisory_source'] + ": " + vulnerability['external_advisory_severity']

    if vulnerability['issue_id']:
        title = vulnerability['issue_id'] + " - " + vulnerability['summary']
    else:
        title = vulnerability['summary']

    references = "\n".join(vulnerability['references'])

    scan_time = datetime.strptime(vulnerability['artifact_scan_time'], "%Y-%m-%dT%H:%M:%S%z")

    # component has several parts separated by colons. Last part is the version, everything else is the name
    splitComponent = vulnerability['vulnerable_component'].split(':')
    component_name = ":".join(splitComponent[:-1])
    component_version = splitComponent[-1:][0]
    # remove package type from component name
    component_name = component_name.split("://", 1)[1]

    tags = ["packagetype_" + vulnerability['package_type']]

    # create the finding object
    finding = Finding(
        title=title,
        cve=cve,
        test=test,
        severity=severity,
        description=(vulnerability['description'] + "\n\n" + extra_desc).strip(),
        mitigation=mitigation,
        component_name=component_name,
        component_version=component_version,
        file_path=vulnerability['path'],
        severity_justification="CVSS v3 base score: {}\nCVSS v2 base score: {}".format(cvss_v3, cvss_v2),
        static_finding=True,
        dynamic_finding=False,
        references=references,
        impact=severity,
        cvssv3=cvssv3,
        date=scan_time,
        unique_id_from_tool=vulnerability['issue_id'],
        tags=tags)

    return finding
