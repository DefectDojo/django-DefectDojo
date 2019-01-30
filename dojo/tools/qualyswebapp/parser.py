#!/usr/bin/env python
#
#-*- coding:utf-8 -*-

import argparse
import csv
from dojo.models import Finding, Endpoint
from urllib.parse import urlparse
################################################################

# Non-standard libraries
try:
    import defusedxml.lxml as lxml
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
                  'cve': 'CVE'}

REPORT_HEADERS = ['CVSS_score',
                  'ip_address',
                  'fqdn',
                  'os',
                  'port_status',
                  'vuln_name',
                  'vuln_description',
                  'solution',
                  'links',
                  'cve']

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

def issue_r(raw_row, vuln, test, issueType):
    ret_rows = []
    issue_row = {}

    _gid = raw_row.findtext('QID')
    _temp = issue_row
    param=None
    payload=None

    if(issueType == "vul"):
        url=raw_row.findtext('URL')
        param=raw_row.findtext('PARAM')
        payload=raw_row.findtext('PAYLOADS/PAYLOAD/PAYLOAD')
        parts = urlparse(url)

        ep=Endpoint(protocol=parts.scheme,
                 host=parts.netloc,
                 path=parts.path,
                 query=parts.query,
                 fragment=parts.fragment,
                 product=test.engagement.product)

    search = "//GLOSSARY/QID_LIST/QID"
    r = vuln.xpath('/WAS_WEBAPP_REPORT/GLOSSARY/QID_LIST/QID')

    for vuln_item in r:
        if vuln_item is not None:
            if vuln_item.findtext('QID') == _gid:
                finding = Finding()

                _temp['vuln_name'] = vuln_item.findtext('TITLE')
                _temp['vuln_solution'] = vuln_item.findtext('SOLUTION')
                _temp['vuln_description'] = htmltext(vuln_item.findtext('DESCRIPTION'))
                _temp['impact'] = htmltext(vuln_item.findtext('IMPACT'))
                _temp['CVSS_score'] = vuln_item.findtext('CVSS_BASE')
                _temp['Severity'] = vuln_item.findtext('SEVERITY')

                if _temp['Severity'] is not None:
                    if float(_temp['Severity']) == 1:
                        _temp['Severity']="Info"
                    elif float(_temp['Severity']) == 2:
                        _temp['Severity'] = "Low"
                    elif float(_temp['Severity']) == 3:
                        _temp['Severity'] = "Medium"
                    elif float(_temp['Severity']) == 4:
                        _temp['Severity'] = "High"
                    else:
                        _temp['Severity'] = "Critical"
                print("Finding None")

                finding = None

                if issueType=="vul":
                    finding = Finding(title=_temp['vuln_name'], mitigation=_temp['vuln_solution'],
                                         description=_temp['vuln_description'], param=param, payload=payload, severity=_temp['Severity'],impact=_temp['impact'])

                    finding.unsaved_endpoints = list()
                    finding.unsaved_endpoints.append(ep)
                else:
                    finding = Finding(title=_temp['vuln_name'], mitigation=_temp['vuln_solution'],
                                         description=_temp['vuln_description'], param=param, payload=payload,
                                         severity=_temp['Severity'],impact=_temp['impact'])

                ret_rows.append(finding)

    return ret_rows

def qualys_webapp_parser(qualys_xml_file,test):
    parser = etree.XMLParser(remove_blank_text=True, no_network=True, recover=True)
    d = etree.parse(qualys_xml_file, parser)

    r = d.xpath('/WAS_WEBAPP_REPORT/RESULTS/WEB_APPLICATION/VULNERABILITY_LIST/VULNERABILITY')
    # r = d.xpath('/WAS_SCAN_REPORT/RESULTS/VULNERABILITY_LIST/VULNERABILITY')
    l = d.xpath('/WAS_WEBAPP_REPORT/RESULTS/WEB_APPLICATION/INFORMATION_GATHERED_LIST/INFORMATION_GATHERED')
    # l = d.xpath('/WAS_SCAN_REPORT/RESULTS/INFORMATION_GATHERED_LIST/INFORMATION_GATHERED')

    master_list = []

    for issue in r:
        master_list += issue_r(issue, d,test,"vul")

    for issue in l:
        master_list += issue_r(issue,d,test,"info")

    return master_list

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
        print(("[!] Error processing file: {}".format(args.qualys_xml_file)))
        exit()

class QualysWebAppParser(object):
    def __init__(self, file, test):
        self.items = qualys_webapp_parser(file,test)
