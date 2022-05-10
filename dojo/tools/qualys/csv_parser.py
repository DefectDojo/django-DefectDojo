import csv
import io
import logging
from datetime import datetime
import re

from dojo.models import Finding, Endpoint

_logger = logging.getLogger(__name__)


def parse_csv(csv_file) -> [Finding]:
    """
    Parses Qualys Report in CSV format
    Args:
        csv_file:
    Returns:
    """

    default_keys = [
        'IP',
        'Network',
        'DNS',
        'NetBIOS',
        'Tracking Method',
        'OS',
        'IP Status',
        'QID',
        'Title',
        'Vuln Status',
        'Type',
        'Severity',
        'Port',
        'Protocol',
        'FQDN',
        'SSL',
        'First Detected',
        'Last Detected',
        'Times Detected',
        'Date Last Fixed',
        'CVE ID',
        'Vendor Reference',
        'Bugtraq ID',
        'CVSS3',
        'CVSS3 Base',
        'CVSS3 Temporal',
        'Threat',
        'Impact',
        'Solution',
        'Exploitability',
        'Associated Malware',
        'PCI Vuln',
        'Ticket State',
        'Instance',
        'OS CPE',
        'Category',
        'Associated Tags']

    content = csv_file.read()
    if isinstance(content, bytes):
        content = content.decode('utf-8')
    csv_reader = csv.DictReader(
        io.StringIO(content),
        delimiter=',',
        quotechar='"',
        fieldnames=default_keys)

    report_findings = get_report_findings(csv_reader)
    dojo_findings = build_findings_from_dict(report_findings)

    return dojo_findings


def get_report_findings(csv_reader) -> [dict]:
    """
    Filters out the unneeded information at the beginning of the Qualys CSV report.
    Args:
        csv_reader:

    Returns:

    """

    report_findings = []

    for row in csv_reader:
        if row.get('Title') and row['Title'] != 'Title':
            report_findings.append(row)

    return report_findings


def get_references(cve_list):
    if cve_list:
        return '\n'.join(
            [f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve.strip()}' for cve in cve_list.split(',')])
    else:
        return None


def _extract_cvss_vectors(cvss_base, cvss_temporal):
    """
    Parses the CVSS3 Vectors from the CVSS3 Base and CVSS3 Temporal fields and returns as a single string.

    This is done because the raw values come with additional characters that cannot be parsed with the cvss library.
        Example: 6.7 (AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)
    Args:
        cvss_base:
        cvss_temporal:
    Returns:
        A CVSS3 Vector including both Base and Temporal if available
    """

    vector_pattern = r'^\d.\d \((.*)\)'

    if cvss_base:
        try:
            cvss_base_vector = re.search(vector_pattern, cvss_base).group(1)
        except IndexError:
            _logger.error(f'CVSS3 Base Vector not found in {cvss_base}')
            return None
        if cvss_temporal:
            try:
                cvss_temporal_vector = re.search(
                    vector_pattern, cvss_temporal).group(1)
                return f'CVSS:3.0/{cvss_base_vector}/{cvss_temporal_vector}'
            except IndexError:
                _logger.error(
                    f'CVSS3 Temporal Vector not found in {cvss_base}')
                return f'CVSS:3.0/{cvss_base_vector}'
        else:
            return cvss_base_vector
    else:
        return None


def build_findings_from_dict(report_findings: [dict]) -> [Finding]:
    """
    Takes a list of Dictionaries built from CSV and creates a Finding object
    Args:
        report_findings:
    Returns:

    """
    severity_lookup = {
        '1': 'Info',
        '2': 'Low',
        '3': 'Medium',
        '4': 'High',
        '5': 'Critical'}
    dojo_findings = []

    for report_finding in report_findings:
        if report_finding.get('FQDN'):
            endpoint = Endpoint.from_uri(report_finding.get('FQDN'))
        else:
            endpoint = Endpoint(host=report_finding['IP'])

        finding = Finding(
            title=f"QID-{report_finding['QID']} | {report_finding['Title']}",
            mitigation=report_finding['Solution'],
            description=report_finding['Threat'],
            severity=severity_lookup.get(
                report_finding['Severity'],
                'Info'),
            references=get_references(
                report_finding['CVE ID']),
            impact=report_finding['Impact'],
            date=datetime.strptime(
                report_finding['Last Detected'],
                "%m/%d/%Y %H:%M:%S").date(),
            vuln_id_from_tool=report_finding['QID'],
            cvssv3=_extract_cvss_vectors(
                    report_finding['CVSS3 Base'],
                report_finding['CVSS3 Temporal']))

        if report_finding['Date Last Fixed']:
            finding.mitigated = datetime.strptime(
                report_finding['Date Last Fixed'],
                "%m/%d/%Y %H:%M:%S").date()
            finding.is_Mitigated = True
        else:
            finding.is_Mitigated = False

        finding.active = report_finding['Vuln Status'] in (
            'Active', 'Re-Opened', 'New')
        finding.verified = True
        finding.unsaved_endpoints = [endpoint]

        dojo_findings.append(finding)

    return dojo_findings
