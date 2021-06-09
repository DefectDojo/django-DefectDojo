import csv
import io
import logging
from datetime import datetime

from dojo.models import Finding, Endpoint


def parse_csv(csv_file) -> [Finding]:
    """
    Parses Qualys Report in CSV format
    Args:
        csv_file:
    Returns:
    """

    default_keys = ['IP', 'Network', 'DNS', 'NetBIOS', 'Tracking Method', 'OS', 'IP Status', 'QID', 'Title',
                    'Vuln Status', 'Type', 'Severity', 'Port', 'Protocol', 'FQDN', 'SSL', 'First Detected',
                    'Last Detected', 'Times Detected', 'Date Last Fixed', 'CVE ID', 'Vendor Reference', 'Bugtraq ID',
                    'CVSS3', 'CVSS3 Base', 'CVSS3 Temporal', 'Threat', 'Impact', 'Solution', 'Exploitability',
                    'Associated Malware', 'PCI Vuln', 'Ticket State', 'Instance', 'OS CPE', 'Category',
                    'Associated Tags']

    content = csv_file.read()
    if type(content) is bytes:
        content = content.decode('utf-8')
    csv_reader = csv.DictReader(io.StringIO(content), delimiter=',', quotechar='"', fieldnames=default_keys)

    report_findings = get_report_findings(csv_reader)
    dojo_findings = build_findings_from_dict(report_findings)


    return dojo_findings


def get_report_findings(csv_reader) ->[dict]:
    """
    Filters out the unneded information at the beginning of the Qualys CSV report.
    Args:
        csv_reader:

    Returns:

    """

    report_findings = []

    for row in csv_reader:
        if row['Title'] and row['Title'] != 'Title':
            report_findings.append(row)

    return report_findings


def build_findings_from_dict(report_findings) -> [Finding]:
    """
    Takes a Dict built from CSV and creates a Finding object
    Args:
        report_findings:
    Returns:

    """
    severity_lookup = {1: 'Informational', 2: 'Low', 3: 'Medium', 4: 'High', 5: ' Critical'}

    dojo_findings = []

    for report_finding in report_findings:
        if report_finding['FQDN']:
            endpoint = Endpoint.from_uri(report_finding['FQDN'])
        else:
            endpoint = Endpoint.from_uri(report_finding['IP'])

        finding = Finding(
            title=f"QID-{report_finding['QID']} | {report_finding['Title']}",
            mitigation=report_finding['Solution'],
            description=report_finding['Threat'],
            severity=severity_lookup.get(report_finding['Severity'], 'Informational'),
            impact=report_finding['Impact'],
            date=datetime.strptime(report_finding['Last Detected'], "%m/%d/%Y %H:%M:%S").date(),
            vuln_id_from_tool=report_finding['QID']
        )

        if report_finding['Date Last Fixed']:
            finding.mitigated = datetime.strptime(report_finding['Date Last Fixed'], "%m/%d/%Y %H:%M:%S").date()
            finding.is_Mitigated = True
        else:
            finding.is_Mitigated = False

        finding.active = report_finding['Vuln Status'] in ('Active', 'Re-Opened', 'New')
        finding.verified = True
        finding.unsaved_endpoints = [endpoint]

        dojo_findings.append(finding)

    return dojo_findings
