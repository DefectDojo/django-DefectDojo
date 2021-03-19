import logging
from datetime import datetime

import html2text
from dateutil import parser
from defusedxml import ElementTree

from dojo.models import Endpoint, Finding

logger = logging.getLogger(__name__)


def htmltext(blob):
    h = html2text.HTML2Text()
    h.ignore_links = False
    return h.handle(blob)


def issue_r(raw_row, vuln, scan_date):
    ret_rows = []
    issue_row = {}

    # IP ADDRESS
    issue_row['ip_address'] = raw_row.get('value')

    # FQDN
    issue_row['fqdn'] = raw_row.get('name')
    if issue_row['fqdn'] == "No registered hostname":
        issue_row['fqdn'] = None
    # port
    _port = raw_row.get('port')

    # Create Endpoint
    if issue_row['fqdn']:
        ep = Endpoint(host=issue_row['fqdn'])
    else:
        ep = Endpoint(host=issue_row['ip_address'])

    # OS NAME
    issue_row['os'] = raw_row.findtext('OS')

    # Scan details - VULNS//VULN indicates we only care about confirmed vulnerabilities
    for vuln_cat in raw_row.findall('VULNS/CAT'):
        _category = str(vuln_cat.get('value'))
        for vuln_details in vuln_cat.findall('VULN'):
            _temp = issue_row

            _gid = vuln_details.get('number')

            _temp['port_status'] = _port

            _result = str(vuln_details.findtext('RESULT'))

            # Vuln name
            _temp['vuln_name'] = vuln_details.findtext('TITLE')

            # Vuln Description
            _description = str(vuln_details.findtext('DIAGNOSIS'))
            # Solution Strips Heading Workaround(s)
            _temp['solution'] = htmltext(str(vuln_details.findtext('SOLUTION')))

            # Vuln_description
            _temp['vuln_description'] = "\n".join([htmltext(_description),
                                                    htmltext("**Category:** " + _category),
                                                    htmltext("**QID:** " + str(_gid)),
                                                    htmltext("**Port:** " + str(_port)),
                                                    htmltext("**Result Evidence:** " + _result),
                                                   ])
            # Impact description
            _temp['IMPACT'] = htmltext(str(vuln_details.findtext('CONSEQUENCE')))

            # CVE and LINKS
            _cl = []
            _temp_cve_details = vuln_details.iterfind('CVE_ID_LIST/CVE_ID')
            if _temp_cve_details:
                _cl = {cve_detail.findtext('ID'): cve_detail.findtext('URL') for cve_detail in _temp_cve_details}
                _temp['cve'] = "\n".join(list(_cl.keys()))
                _temp['links'] = "\n".join(list(_cl.values()))

            # The CVE in Qualys report might not have a CVSS score, so findings are informational by default
            # unless we can find map to a Severity OR a CVSS score from the findings detail.
            sev = qualys_convert_severity(vuln_details.get('severity'))

            refs = "\n".join(list(_cl.values()))
            finding = Finding(title=_temp['vuln_name'],
                                    mitigation=_temp['solution'],
                                    description=_temp['vuln_description'],
                                    severity=sev,
                                    references=refs,
                                    impact=_temp['IMPACT'],
                                    vuln_id_from_tool=_gid,
                                    date=scan_date,
                              )
            finding.unsaved_endpoints = list()
            finding.unsaved_endpoints.append(ep)
            ret_rows.append(finding)
    return ret_rows


def qualys_convert_severity(raw_val):
    val = str(raw_val).strip()
    if '1' == val:
        return 'Info'
    elif '2' == val:
        return 'Low'
    elif '3' == val:
        return 'Medium'
    elif '4' == val:
        return 'High'
    elif '5' == val:
        return 'Critical'
    else:
        return 'Info'


class QualysInfrascanWebguiParser(object):

    def get_scan_types(self):
        return ["Qualys Infrastructure Scan (WebGUI XML)"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Qualys WebGUI output files can be imported in XML format."

    def get_findings(self, file, test):
        data = ElementTree.parse(file).getroot()

        # fetch scan date e.g.: <KEY value="DATE">2020-01-30T09:45:41Z</KEY>
        scan_date = datetime.now()
        for i in data.findall('HEADER/KEY'):
            if i.get('value') == 'DATE':
                scan_date = parser.isoparse(i.text)

        master_list = []
        for issue in data.findall('IP'):
            master_list += issue_r(issue, data, scan_date)
        return master_list
