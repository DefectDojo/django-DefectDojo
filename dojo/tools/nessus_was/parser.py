import csv
import io
import logging
import re
import sys
from defusedxml import ElementTree
from dojo.models import Endpoint, Finding, Test

LOGGER = logging.getLogger(__name__)


class NessusWASCSVParser(object):

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

    def get_findings(self, filename, test: Test):
        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        csv.field_size_limit(int(sys.maxsize / 10))  # the request/resp are big
        reader = csv.DictReader(io.StringIO(content))
        dupes = dict()
        for row in reader:
            # get title, skip entries with empty titles
            title = row.get('Name')
            if not title:
                continue
            # get description, mitigation, impact etc. from respective columns
            description = row.get('Synopsis')
            mitigation = str(row.get('Solution'))
            impact = row.get('Description')
            references = row.get('See Also')
            cvssv3 = row.get('CVSSv3', None)
            protocol = row.get('Protocol').lower() if 'Protocol' in row else None
            port = row.get('Port', None)
            host = row.get('Host', row.get('IP Address', 'localhost'))

            # get severity from 'Risk' column and manage columns with no 'Risk' value
            severity = self._convert_severity(row.get('Risk'))
            if 'CVE' in row:
                vulnerability_ids = self._format_cve(str(row.get('CVE')))
            else:
                vulnerability_ids = None

            # manage multiple columns falling under one category (e.g. description being synopsis + plugin output)
            dupe_key = severity + title + row.get('Host', 'No host') + str(row.get('Port', 'No port')) + row.get('Synopsis', 'No synopsis')
            if dupe_key in dupes:
                find = dupes[dupe_key]
                if 'Plugin Output' in row:
                    find.description += row.get('Plugin Output')
            else:
                if 'Plugin Output' in row:
                    description = description + str(row.get('Plugin Output'))
                find = Finding(title=title,
                                test=test,
                                description=description,
                                severity=severity,
                                mitigation=mitigation,
                                impact=impact,
                                references=references)
                if cvssv3:
                    find.cvssv3_score = cvssv3
                if vulnerability_ids:
                    find.unsaved_vulnerability_ids = vulnerability_ids
                find.unsaved_endpoints = list()
                dupes[dupe_key] = find
            # manage endpoints
            if '://' in host:
                endpoint = Endpoint.from_uri(host)
            else:
                endpoint = Endpoint(
                    protocol=protocol,
                    host=host,
                    port=port)
            find.unsaved_endpoints.append(endpoint)

        return list(dupes.values())


class NessusWASXMLParser(object):
    def get_findings(self, file, test):
        nscan = ElementTree.parse(file)
        root = nscan.getroot()

        if 'NessusClientData_v2' not in root.tag:
            raise ValueError('This version of Nessus report is not supported. Please make sure the export is '
                               'formatted using the NessusClientData_v2 schema.')
        dupes = {}
        for report in root.iter("Report"):
            for host in report.iter("ReportHost"):
                ip = host.attrib['name']
                fqdn = host.find(".//HostProperties/tag[@name='host-fqdn']").text if host.find(
                    ".//HostProperties/tag[@name='host-fqdn']") is not None else None

                for item in host.iter("ReportItem"):
                    port = None
                    if float(item.attrib["port"]) > 0:
                        port = item.attrib["port"]

                    protocol = None
                    if str(item.attrib["svc_name"]):
                        protocol = re.sub(r'[^A-Za-z0-9\-\+]+', "", item.attrib["svc_name"])
                        if protocol == 'www':
                            protocol = 'http'

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
                    if item.findtext("description"):
                        impact = item.find("description").text + "\n\n"
                    if item.findtext("cvss"):
                        impact += "CVSS Score: " + item.find("cvss").text + "\n"
                    if item.findtext("cvssv3"):
                        impact += "CVSSv3 Score: " + item.find("cvssv3").text + "\n"

                    mitigation = item.find("solution").text if item.find("solution") is not None else "N/A"
                    references = ""
                    for ref in item.iter("see_also"):
                        refs = ref.text.split()
                        for r in refs:
                            references += r + "\n"

                    for xref in item.iter("xref"):
                        references += xref.text + "\n"

                    vunerability_id = None
                    if item.findtext("cve"):
                        vunerability_id = item.find("cve").text
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
                                       cwe=cwe)
                        if vunerability_id:
                            find.unsaved_vulnerability_ids = [vunerability_id]
                        find.unsaved_endpoints = list()
                        dupes[dupe_key] = find

                    if '://' in fqdn:
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


class NessusWASParser(object):

    def get_scan_types(self):
        return ["Nessus WAS Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Nessus WAS Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Reports can be imported as CSV or .nessus (XML) report formats."

    def get_findings(self, filename, test):

        if filename.name.lower().endswith('.xml') or filename.name.lower().endswith('.nessus'):
            return NessusWASXMLParser().get_findings(filename, test)
        elif filename.name.lower().endswith('.csv'):
            return NessusWASCSVParser().get_findings(filename, test)
        else:
            raise ValueError('Filename extension not recognized. Use .xml, .nessus or .csv')
