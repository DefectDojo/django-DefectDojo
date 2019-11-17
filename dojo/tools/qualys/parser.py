#!/usr/bin/env python
#
# by John Kim
# Thanks to Securicon, LLC. for sponsoring development
#
# -*- coding:utf-8 -*-

# Modified by Greg

import argparse
import csv
import re
from dojo.models import Finding, Endpoint
################################################################

# Non-standard libraries
try:
    from lxml import etree
except ImportError:
    print("Missing lxml library. Please install using PIP. https://pypi.python.org/pypi/lxml/3.4.2")
    exit()

try:
    import html2text
except ImportError:
    print("Missing html2text library. Please install using PIP. https://pypi.python.org/pypi/html2text/2015.2.18")
    exit()

# Custom libraries
try:
    from . import utfdictcsv
except ImportError:
    print("Missing dict to csv converter custom library. utfdictcsv.py should be in the same path as this file.")
    exit()

################################################################

CUSTOM_HEADERS = {'CVSS_score': 'CVSS Score',
                  'ip_address': 'IP Address',
                  'fqdn': 'FQDN',
                  'os': 'OS',
                  'port_status': 'Port',
                  'vuln_name': 'Vulnerability',
                  'vuln_description': 'Description',
                  'solution': 'Solution',
                  'links': 'Links',
                  'cve': 'CVE',
                  'vuln_severity': 'Severity',
                  'QID': 'QID',
                  'first_found': 'First Found',
                  'last_found': 'Last Found',
                  'found_times': 'Found Times',
                  'category': 'Category'
                  }

REPORT_HEADERS = ['CVSS_score',
                  'ip_address',
                  'fqdn',
                  'os',
                  'port_status',
                  'vuln_name',
                  'vuln_description',
                  'solution',
                  'links',
                  'cve',
                  'Severity',
                  'QID',
                  'first_found',
                  'last_found',
                  'found_times',
                  'category',
                  ]

################################################################


def htmltext(blob):
    h = html2text.HTML2Text()
    h.ignore_links = False
    return h.handle(blob)


def report_writer(report_dic, output_filename):
    with open(output_filename, "wb") as outFile:
        csvWriter = utfdictcsv.DictUnicodeWriter(outFile, REPORT_HEADERS, quoting=csv.QUOTE_ALL)
        csvWriter.writerow(CUSTOM_HEADERS)
        csvWriter.writerows(report_dic)
    print("Successfully parsed.")

################################################################


def issue_r(raw_row, vuln):
    ret_rows = []
    issue_row = {}

    # IP ADDRESS
    issue_row['ip_address'] = raw_row.findtext('IP')

    # FQDN
    issue_row['fqdn'] = raw_row.findtext('DNS')

    # Create Endpoint
    if issue_row['fqdn']:
        ep = Endpoint(host=issue_row['fqdn'])
    else:
        ep = Endpoint(host=issue_row['ip_address'])

    # OS NAME
    issue_row['os'] = raw_row.findtext('OPERATING_SYSTEM')

    # Scan details
    for vuln_details in raw_row.iterfind('VULN_INFO_LIST/VULN_INFO'):
        _temp = issue_row
        # Port
        _gid = vuln_details.find('QID').attrib['id']
        _port = vuln_details.findtext('PORT')
        _temp['port_status'] = _port

        _category = str(vuln_details.findtext('CATEGORY'))
        _result = str(vuln_details.findtext('RESULT'))
        _first_found = str(vuln_details.findtext('FIRST_FOUND'))
        _last_found = str(vuln_details.findtext('LAST_FOUND'))
        _times_found = str(vuln_details.findtext('TIMES_FOUND'))
        search = "//GLOSSARY/VULN_DETAILS_LIST/VULN_DETAILS[@id='{}']".format(_gid)
        vuln_item = vuln.find(search)
        if vuln_item is not None:
            finding = Finding()
            # Vuln name
            _temp['vuln_name'] = vuln_item.findtext('TITLE')

            # Vuln Description
            _description = str(vuln_item.findtext('THREAT'))
            # Solution Strips Heading Workaround(s)
            # _temp['solution'] = re.sub('Workaround(s)?:.+\n', '', htmltext(vuln_item.findtext('SOLUTION')))
            _temp['solution'] = htmltext(vuln_item.findtext('SOLUTION'))

            # Vuln_description
            _temp['vuln_description'] = "\n".join([htmltext(_description),
                                                   htmltext("Category: " + _category),
                                                   htmltext("QID: " + str(_gid)),
                                                   htmltext("Port: " + str(_port)),
                                                   htmltext("Result Evidence: " + _result),
                                                   htmltext("First Found: " + _first_found),
                                                   htmltext("Last Found: " + _last_found),
                                                   htmltext("Times Found: " + _times_found),
                                                   ])
            # Impact description
            _temp['IMPACT'] = htmltext(vuln_item.findtext('IMPACT'))

            # CVSS
            _temp['CVSS_score'] = vuln_item.findtext('CVSS_SCORE/CVSS_BASE')

            # CVE and LINKS
            _temp_cve_details = vuln_item.iterfind('CVE_ID_LIST/CVE_ID')
            if _temp_cve_details:
                _cl = {cve_detail.findtext('ID'): cve_detail.findtext('URL') for cve_detail in _temp_cve_details}
                _temp['cve'] = "\n".join(list(_cl.keys()))
                _temp['links'] = "\n".join(list(_cl.values()))
        # The CVE in Qualys report might not have a CVSS score, so findings are informational by default
        # unless we can find map to a Severity OR a CVSS score from the findings detail.
        sev = None
        if _temp['CVSS_score'] is not None and float(_temp['CVSS_score']) > 0:
            if 0.1 <= float(_temp['CVSS_score']) <= 3.9:
                sev = 'Low'
            elif 4.0 <= float(_temp['CVSS_score']) <= 6.9:
                sev = 'Medium'
            elif 7.0 <= float(_temp['CVSS_score']) <= 8.9:
                sev = 'High'
            elif float(_temp['CVSS_score']) >= 9.0:
                sev = 'Critical'
        elif vuln_item.findtext('SEVERITY') is not None:
            if int(vuln_item.findtext('SEVERITY')) == 1:
                sev = 'Informational'
            elif int(vuln_item.findtext('SEVERITY')) == 2:
                sev = 'Low'
            elif int(vuln_item.findtext('SEVERITY')) == 3:
                sev = 'Medium'
            elif int(vuln_item.findtext('SEVERITY')) == 4:
                sev = 'High'
            elif int(vuln_item.findtext('SEVERITY')) == 5:
                sev = 'Critical'
        elif sev is None:
            sev = 'Informational'
        finding = None
        if _temp_cve_details:
            refs = "\n".join(list(_cl.values()))
            finding = Finding(title=_temp['vuln_name'],
                              mitigation=_temp['solution'],
                              description=_temp['vuln_description'],
                              severity=sev,
                              references=refs,
                              impact=_temp['IMPACT'],
                              )

        else:
            finding = Finding(title=_temp['vuln_name'],
                              mitigation=_temp['solution'],
                              description=_temp['vuln_description'],
                              severity=sev,
                              references=_gid,
                              impact=_temp['IMPACT'],
                              )
        finding.unsaved_endpoints = list()
        finding.unsaved_endpoints.append(ep)
        ret_rows.append(finding)
    return ret_rows


def qualys_parser(qualys_xml_file):
    parser = etree.XMLParser(remove_blank_text=True, no_network=True, recover=True)
    d = etree.parse(qualys_xml_file, parser)
    r = d.xpath('//ASSET_DATA_REPORT/HOST_LIST/HOST')
    master_list = []

    for issue in r:
        master_list += issue_r(issue, d)
    return master_list
    # report_writer(master_list, args.outfile)

################################################################


if __name__ == "__main__":

    # Parse args
    aparser = argparse.ArgumentParser(description='Converts Qualys XML results to .csv file.')
    aparser.add_argument('--out',
                        dest='outfile',
                        default='qualys.csv',
                        help="WARNING: By default, output will overwrite current path to the file named 'qualys.csv'")

    aparser.add_argument('qualys_xml_file',
                        type=str,
                        help='Qualys xml file.')

    args = aparser.parse_args()

    try:
        qualys_parser(args.qualys_xml_file)
    except IOError:
        print("[!] Error processing file: {}".format(args.qualys_xml_file))
        exit()


class QualysParser(object):
    def __init__(self, file, test):
        self.items = qualys_parser(file)
