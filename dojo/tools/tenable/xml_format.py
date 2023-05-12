import logging
import re

from cvss import CVSS3
from defusedxml import ElementTree
from hyperlink._url import SCHEME_PORT_MAP

from dojo.models import Endpoint, Finding, Test

LOGGER = logging.getLogger(__name__)


class TenableXMLParser(object):
    def get_text_severity(self, severity_id):
        """Convert data of the report into severity"""
        if severity_id == 4:
            return "Critical"
        elif severity_id == 3:
            return "High"
        elif severity_id == 2:
            return "Medium"
        elif severity_id == 1:
            return "Low"
        else:
            return "Info"

    def get_findings(self, filename: str, test: Test) -> list:
        # Read the XML
        nscan = ElementTree.parse(filename)
        root = nscan.getroot()
        dupes = {}
        for report in root.iter("Report"):
            for host in report.iter("ReportHost"):
                ip = host.attrib.get("name")
                fqdn = host.find('.//HostProperties/tag[@name="host-fqdn"]').text if host.find('.//HostProperties/tag[@name="host-fqdn"]') is not None else None

                for item in host.iter("ReportItem"):
                    # Set the title
                    title = item.attrib.get("pluginName")

                    # Get and clean the port
                    port = None
                    if float(item.attrib.get("port")) > 0:
                        port = item.attrib.get("port")

                    # Get and clean the protocol
                    protocol = str(item.attrib.get("svc_name", None))
                    if protocol:
                        protocol = re.sub(r"[^A-Za-z0-9\-\+]+", "", protocol)
                        if protocol == "www":
                            protocol = "http"
                        if protocol not in SCHEME_PORT_MAP:
                            protocol = re.sub(r"[^A-Za-z0-9\-\+]+", "", item.attrib.get("protocol", protocol))

                    # Set the description with a few different fields
                    description = ""
                    plugin_output = None
                    if item.findtext("synopsis"):
                        description = item.find("synopsis").text + "\n\n"
                    if item.findtext("plugin_output"):
                        plugin_output = f"Plugin Output: {ip}{str(f':{port}' if port is not None else '')}"
                        plugin_output += f"\n```\n{str(item.find('plugin_output').text)}\n```\n\n"
                        description += plugin_output

                    # Determine the severity
                    nessus_severity_id = int(item.attrib.get("severity"))
                    severity = self.get_text_severity(nessus_severity_id)

                    # Build up the impact
                    impact = ""
                    if item.find("description"):
                        impact = item.find("description").text + "\n\n"
                    if item.findtext("cvss"):
                        impact += "CVSS Score: " + item.find("cvss").text + "\n"
                    if item.findtext("cvssv3"):
                        impact += "CVSSv3 Score: " + item.find("cvssv3").text + "\n"
                    if item.findtext("cvss_vector"):
                        impact += "CVSS Vector: " + item.find("cvss_vector").text + "\n"
                    if item.findtext("cvss_base_score"):
                        impact += "CVSS Base Score: " + item.find("cvss_base_score").text + "\n"
                    if item.findtext("cvss_temporal_score"):
                        impact += "CVSS Temporal Score: " + item.find("cvss_temporal_score").text + "\n"

                    # Set the mitigation
                    mitigation = item.find("solution").text if item.find("solution") is not None else "N/A"

                    # Build up the references
                    references = ""
                    for ref in item.iter("see_also"):
                        refs = ref.text.split()
                        for r in refs:
                            references += r + "\n"
                    for xref in item.iter("xref"):
                        references += xref.text + "\n"

                    # Build out the scoreing
                    vulnerability_id = None
                    if item.findtext("cve"):
                        vulnerability_id = item.find("cve").text
                    cwe = None
                    if item.findtext("cwe"):
                        cwe = item.find("cwe").text
                    cvssv3 = None
                    if item.findtext("cvss3_vector"):
                        cvssv3 = CVSS3(item.findtext("cvss3_vector")).clean_vector(output_prefix=True)

                    # Determine the current entry has already been parsed in this report
                    dupe_key = severity + title
                    if dupe_key not in dupes:
                        find = Finding(
                            title=title,
                            test=test,
                            description=description,
                            severity=severity,
                            mitigation=mitigation,
                            impact=impact,
                            references=references,
                            cwe=cwe,
                            cvssv3=cvssv3
                        )
                        find.unsaved_endpoints = []
                        find.unsaved_vulnerability_ids = []
                        dupes[dupe_key] = find
                    else:
                        find = dupes[dupe_key]
                        if plugin_output is not None:
                            find.description += plugin_output

                    # Update existing vulnerability IDs
                    if vulnerability_id:
                        find.unsaved_vulnerability_ids.append(vulnerability_id)

                    # Create a new endpoint object
                    if fqdn and "://" in fqdn:
                        endpoint = Endpoint.from_uri(fqdn)
                    elif protocol == "general":
                        endpoint = Endpoint(host=fqdn if fqdn else ip)
                    else:
                        endpoint = Endpoint(protocol=protocol,
                                            host=fqdn if fqdn else ip,
                                            port=port)
                    find.unsaved_endpoints.append(endpoint)

        return list(dupes.values())
