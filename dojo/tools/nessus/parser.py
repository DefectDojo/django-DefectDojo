import csv
import io
import logging
import re
import sys
from xml.dom import NamespaceErr

from cpe import CPE
from cvss import CVSS3
from defusedxml import ElementTree
from hyperlink._url import SCHEME_PORT_MAP

from dojo.models import Endpoint, Finding, Test

LOGGER = logging.getLogger(__name__)


class NessusCSVParser(object):

    def _convert_severity(self, val):
        if "None" == val:
            return 'Info'
        if val is None:
            return 'Info'
        else:
            return val.title()

    def _format_cve(self, val):
        if val is None:
            return None
        elif "" == val:
            return None
        cve_match = re.findall(r"CVE-[0-9]+-[0-9]+", val.upper(), re.IGNORECASE)
        if cve_match:
            return cve_match
        return None

    def _format_cpe(self, val):
        if val is None:
            return None
        elif "" == val:
            return None
        cpe_match = re.findall(r"cpe:/[^\n\ ]+", val)
        if cpe_match:
            return cpe_match
        return None

    def get_findings(self, filename, test: Test):
        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        csv.field_size_limit(int(sys.maxsize / 10))  # the request/resp are big
        reader = csv.DictReader(io.StringIO(content))
        dupes = dict()
        for row in reader:
            # manage severity from two possible columns 'Severity' and 'Risk'
            severity = 'Info'
            if 'Severity' in row:
                severity = self._convert_severity(row.get('Severity'))
            elif 'Risk' in row:
                severity = self._convert_severity(row.get('Risk'))
            # manage title from two possible columns 'Nme' and 'Plugin Name'
            title = row.get('Name')
            if title is None and 'Plugin Name' in row:
                title = row.get('Plugin Name')
            # special case to skip empty titles
            if not title:
                continue
            description = row.get('Synopsis')
            mitigation = str(row.get('Solution'))
            impact = row.get('Description', 'N/A')
            references = row.get('See Also', 'N/A')

            dupe_key = severity + title + row.get('Host', 'No host') + str(row.get('Port', 'No port')) + row.get('Synopsis', 'No synopsis')

            detected_cve = self._format_cve(str(row.get('CVE')))
            cve = None
            if detected_cve:
                # FIXME support more than one CVE in Nessus CSV parser
                cve = detected_cve[0]
                if len(detected_cve) > 1:
                    LOGGER.debug("more than one CVE for a finding. NOT supported by Nessus CSV parser")

            if dupe_key in dupes:
                find = dupes[dupe_key]
                if 'Plugin Output' in row:
                    find.description += row.get('Plugin Output')
            else:
                if 'Plugin Output' in row:
                    description = description + str(row.get('Plugin Output'))
                find = Finding(title=title,
                                test=test,
                                cve=cve,
                                description=description,
                                severity=severity,
                                mitigation=mitigation,
                                impact=impact,
                                references=references)

                # manage CVSS vector (only v3.x for now)
                if 'CVSS V3 Vector' in row and '' != row.get('CVSS V3 Vector'):
                    find.cvssv3 = CVSS3('CVSS:3.0/' + str(row.get('CVSS V3 Vector'))).clean_vector(output_prefix=False)
                # manage CPE data
                detected_cpe = self._format_cpe(str(row.get('CPE')))
                if detected_cpe:
                    # FIXME support more than one CPE in Nessus CSV parser
                    if len(detected_cpe) > 1:
                        LOGGER.debug("more than one CPE for a finding. NOT supported by Nessus CSV parser")
                    cpe_decoded = CPE(detected_cpe[0])
                    find.component_name = cpe_decoded.get_product()[0] if len(cpe_decoded.get_product()) > 0 else None
                    find.component_version = cpe_decoded.get_version()[0] if len(cpe_decoded.get_version()) > 0 else None

                find.unsaved_endpoints = list()
                dupes[dupe_key] = find
            # manage endpoints
            host = row.get('Host', row.get('DNS Name'))
            if len(host) == 0:
                host = row.get('IP Address', 'localhost')

            endpoint = Endpoint(
                          protocol=row.get('Protocol').lower() if 'Protocol' in row else None,
                          host=host,
                          port=row.get('Port')
                        )
            find.unsaved_endpoints.append(endpoint)
        return list(dupes.values())


class NessusXMLParser(object):
    def get_findings(self, file, test):
        nscan = ElementTree.parse(file)
        root = nscan.getroot()

        if 'NessusClientData_v2' not in root.tag:
            raise NamespaceErr('This version of Nessus report is not supported. Please make sure the export is '
                               'formatted using the NessusClientData_v2 schema.')
        dupes = {}
        for report in root.iter("Report"):
            for host in report.iter("ReportHost"):
                ip = host.attrib['name']
                fqdn = host.find(".//HostProperties/tag[@name='host-fqdn']").text if host.find(
                    ".//HostProperties/tag[@name='host-fqdn']") is not None else None

                for item in host.iter("ReportItem"):
                    # if item.attrib["svc_name"] == "general":
                    #     continue

                    port = None
                    if float(item.attrib["port"]) > 0:
                        port = item.attrib["port"]

                    protocol = None
                    if str(item.attrib["svc_name"]):
                        protocol = re.sub(r'[^A-Za-z0-9\-\+]+', "", item.attrib["svc_name"])
                        if protocol == 'www':
                            protocol = 'http'
                        if protocol not in SCHEME_PORT_MAP:
                            protocol = re.sub(r'[^A-Za-z0-9\-\+]+', "", item.attrib["protocol"])

                    description = ""
                    plugin_output = None
                    if item.findtext("synopsis"):
                        description = item.find("synopsis").text + "\n\n"
                    if item.findtext("plugin_output"):
                        plugin_output = "Plugin Output: " + ip + (
                            (":" + port) if port is not None else "") + \
                            " \n```\n" + item.find("plugin_output").text + \
                            "\n```\n\n"
                        description += plugin_output

                    nessus_severity_id = int(item.attrib["severity"])
                    severity = self.get_text_severity(nessus_severity_id)

                    impact = ""
                    if item.find("description"):
                        impact = item.find("description").text + "\n\n"
                    if item.findtext("cvss_vector"):
                        impact += "CVSS Vector: " + item.find("cvss_vector").text + "\n"
                    if item.findtext("cvss_base_score"):
                        impact += "CVSS Base Score: " + item.find("cvss_base_score").text + "\n"
                    if item.findtext("cvss_temporal_score"):
                        impact += "CVSS Temporal Score: " + item.find("cvss_temporal_score").text + "\n"

                    mitigation = item.find("solution").text if item.find("solution") is not None else "N/A"
                    references = ""
                    for ref in item.iter("see_also"):
                        refs = ref.text.split()
                        for r in refs:
                            references += r + "\n"

                    for xref in item.iter("xref"):
                        references += xref.text + "\n"

                    cve = None
                    if item.findtext("cve"):
                        cve = item.find("cve").text
                    cwe = None
                    if item.findtext("cwe"):
                        cwe = item.find("cwe").text
                    title = item.attrib["pluginName"]
                    dupe_key = severity + title

                    if dupe_key in dupes:
                        find = dupes[dupe_key]
                        if plugin_output is not None:
                            find.description += plugin_output
                    else:
                        find = Finding(title=title,
                                       test=test,
                                       description=description,
                                       severity=severity,
                                       mitigation=mitigation,
                                       impact=impact,
                                       references=references,
                                       cwe=cwe,
                                       cve=cve)
                        find.unsaved_endpoints = list()
                        dupes[dupe_key] = find

                    if fqdn and '://' in fqdn:
                        endpoint = Endpoint.from_uri(fqdn)
                    else:
                        if protocol == 'general':
                            endpoint = Endpoint(host=fqdn if fqdn else ip)
                        else:
                            endpoint = Endpoint(protocol=protocol,
                                                host=fqdn if fqdn else ip,
                                                port=port)
                    find.unsaved_endpoints.append(endpoint)

        return list(dupes.values())

    def get_text_severity(self, severity_id):
        """Convert data of the report into severity"""
        if severity_id == 4:
            return 'Critical'
        elif severity_id == 3:
            return 'High'
        elif severity_id == 2:
            return 'Medium'
        elif severity_id == 1:
            return 'Low'
        else:
            return 'Info'


class NessusParser(object):

    def get_scan_types(self):
        return ["Nessus Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Nessus Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Reports can be imported as CSV or .nessus (XML) report formats."

    def get_findings(self, filename, test):

        if filename.name.lower().endswith('.xml') or filename.name.lower().endswith('.nessus'):
            return NessusXMLParser().get_findings(filename, test)
        elif filename.name.lower().endswith('.csv'):
            return NessusCSVParser().get_findings(filename, test)
        else:
            raise ValueError('Filename extension not recognized. Use .xml, .nessus or .csv')
