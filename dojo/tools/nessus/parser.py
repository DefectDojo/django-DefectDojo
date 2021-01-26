import logging
from xml.dom import NamespaceErr
from defusedxml import ElementTree
import csv
import os
import re
from dojo.models import Endpoint, Finding, Test
from cvss import CVSS3
from cpe import CPE

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

    def get_findings(self, filename, test: Test):
        if filename is None:
            return list()

        reader = csv.DictReader(filename, lineterminator='\n', quotechar='"') # quoting=csv.QUOTE_MINIMAL)
        dupes = {}
        first = True
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
            # import json
            # print(f"{json.dumps(row.get('Name'))}")
            # special case to skip empty titles
            if not title:
                continue
            description = row.get('Synopsis')
            mitigation = row.get('Solution', 'N/A')
            impact = row.get('Description', 'N/A')
            references = row.get('See Also', 'N/A')

            dupe_key = severity + title + row.get('Host', 'No host') + row.get('Port', 'No port') + row.get('Synopsis', 'No synopsis')

            detected_cve = self._format_cve(row.get('CVE'))
            cve = None
            if detected_cve:
                # FIXME support more than one CVE in Nessus CSV parser
                cve = detected_cve[0]
                if len(detected_cve) > 1:
                    LOGGER.warning(f"more than one CVE for a finding. NOT supported by Nessus CSV parser '{row.get('CVE')}'")

            if dupe_key in dupes:
                find = dupes[dupe_key]
                if 'Plugin Output' in row:
                    find.description += row.get('Plugin Output')
            else:
                if 'Plugin Output' in row:
                    description = description + row.get('Plugin Output')
                find = Finding(title=title,
                                test=test,
                                active=False,
                                cve=cve,
                                verified=False,
                                description=description,
                                severity=severity,
                                numerical_severity=Finding.get_numerical_severity(severity),
                                mitigation=mitigation,
                                impact=impact,
                                references=references)

                # manage CVSS vector (only v3.x for now)
                if 'CVSS V3 Vector' in row and "" != row.get('CVSS V3 Vector'):
                    find.cvssv3 = CVSS3('CVSS:3.0/' + row.get('CVSS V3 Vector')).clean_vector()
                # manage CPE data
                # TODO for now we will ignore it
                # current implementation is more SCA oriented
                # if 'CPE' in row and "" != row.get('CPE'):
                #     # FIXME this field could have more than one CPE string
                #     cpe_decoded = CPE(row.get('CPE'))
                #     find.component_name = cpe.get_product()[0] if len(cpe.get_product()) > 0 else None
                #     find.component_version = cpe.get_version()[0] if len(cpe.get_version()) > 0 else None

                find.unsaved_endpoints = list()
                dupes[dupe_key] = find
            # manage endpoints
            endpoint = Endpoint(host='localhost')
            if 'Host' in row:
                endpoint.host = row.get('Host')
            elif 'IP Address' in row:
                endpoint.host = row.get('IP Address')
            endpoint.port = row.get('Port')
            if 'Protocol' in row:
                endpoint.protocol = row.get('Protocol').lower()
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
                    if str(item.attrib["protocol"]):
                        protocol = item.attrib["protocol"]

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
                                       active=False,
                                       verified=False,
                                       description=description,
                                       severity=severity,
                                       numerical_severity=Finding.get_numerical_severity(severity),
                                       mitigation=mitigation,
                                       impact=impact,
                                       references=references,
                                       cwe=cwe,
                                       cve=cve)
                        find.unsaved_endpoints = list()
                        dupes[dupe_key] = find

                    find.unsaved_endpoints.append(Endpoint(host=ip + (":" + port if port is not None else ""),
                                                           protocol=protocol))
                    if fqdn is not None:
                        find.unsaved_endpoints.append(Endpoint(host=fqdn,
                                                               protocol=protocol))

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
    def get_findings(self, filename, test):

        if filename is None:
            return list()

        if filename.name.lower().endswith('.xml'):
            return list(NessusXMLParser().parse(filename, test).values())
        elif filename.name.lower().endswith('.csv'):
            return list(NessusCSVParser().parse(filename, test).values())
        else:
            raise ValueError('Unknown File Format')
