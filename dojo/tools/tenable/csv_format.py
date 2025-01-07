import contextlib
import csv
import io
import logging
import re
import sys

from cpe import CPE
from cvss import CVSS3

from dojo.models import Endpoint, Finding, Test

LOGGER = logging.getLogger(__name__)


class TenableCSVParser:
    def _validated_severity(self, severity):
        if severity not in Finding.SEVERITIES:
            severity = "Info"
        return severity

    def _int_severity_conversion(self, severity_value):
        """Convert data of the report into severity"""
        severity = "Info"
        if severity_value == 4:
            severity = "Critical"
        elif severity_value == 3:
            severity = "High"
        elif severity_value == 2:
            severity = "Medium"
        elif severity_value == 1:
            severity = "Low"
        # Ensure the severity is a valid choice. Fall back to info otherwise
        return self._validated_severity(severity)

    def _string_severity_conversion(self, severity_value):
        """Convert data of the report into severity"""
        if severity_value is None or len(severity_value) == 0:
            return "Info"
        severity = severity_value.title()
        return self._validated_severity(severity)

    def _convert_severity(self, severity_value):
        if isinstance(severity_value, int):
            return self._int_severity_conversion(severity_value)
        if isinstance(severity_value, str):
            return self._string_severity_conversion(severity_value)
        return "Info"

    def _format_cve(self, val):
        if val is None or val == "":
            return None
        cve_match = re.findall(
            r"CVE-[0-9]+-[0-9]+", val.upper(), re.IGNORECASE,
        )
        if cve_match:
            return cve_match
        return None

    def _format_cpe(self, val):
        if val is None or val == "":
            return None
        cpe_match = re.findall(r"cpe:/[^\n\ ]+", val)
        return cpe_match or None

    def detect_delimiter(self, content: str):
        """Detect the delimiter of the CSV file"""
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        first_line = content.split("\n")[0]
        if ";" in first_line:
            return ";"
        return ","  # default to comma if no semicolon found

    def get_description(self, row):
        if not row:
            return None

        data_plugin = row.get("Plugin", "")
        data_plugin_name = row.get("Plugin Name", "")
        data_severity = row.get("Severity", "")
        data_ip_address = row.get("IP Address", "")
        data_protocol = row.get("Protocol", "")
        data_port = row.get("Port", "")
        data_exploit = row.get("Exploit?", "")
        data_mac_address = row.get("MAC Address", "")
        data_dns_name = row.get("DNS Name", "")
        data_netbios_name = row.get("NetBIOS Name", "")
        data_plugin_output = row.get("Plugin Output", "")
        data_first_discovered = row.get("First Discovered", "")
        data_last_observed = row.get("Last Observed", "")
        data_exploit_frameworks = row.get("Exploit Frameworks", "")
        data_synopsis = row.get("Synopsis", "")
        data_description = row.get("Description", "")
        data_solution = row.get("Solution", "")
        data_see_also = row.get("See Also", "")
        data_risk_factor = row.get("Risk Factor", "")
        data_stig_severity = row.get("STIG Severity", "")
        data_vpr = row.get("Vulnerability Priority Rating", "")
        data_cvss_v2_base = row.get("CVSS V2 Base Score", "")
        data_cvss_v3_base = row.get("CVSS V3 Base Score", "")
        data_cvss_v2_temporal = row.get("CVSS V2 Temporal Score", "")
        data_cvss_v3_temporal = row.get("CVSS V3 Temporal Score", "")
        data_cvss_v2_vector = row.get("CVSS V2 Vector", "")
        data_cvss_v3_vector = row.get("CVSS V3 Vector", "")
        data_cpe = row.get("CPE", "")
        data_cve = row.get("CVE", "")
        data_bid = row.get("BID", "")
        data_cross_references = row.get("Cross References", "")
        data_vuln_pub_date = row.get("Vuln Publication Date", "")
        data_patch_pub_date = row.get("Patch Publication Date", "")
        data_plugin_pub_date = row.get("Plugin Publication Date", "")
        data_plugin_mod_date = row.get("Plugin Modification Date", "")
        data_exploit_ease = row.get("Exploit Ease", "")
        data_check_type = row.get("Check Type", "")
        data_version = row.get("Version", "")
        data_custom_id = row.get("Custom Id", "")
        return (
        "<p><strong>Plugin:</strong> " + str(data_plugin) + "</p>"
        + "<p><strong>Plugin Name:</strong> " + str(data_plugin_name) + "</p>"
        + "<p><strong>Severity:</strong> " + str(data_severity) + "</p>"
        + "<p><strong>IP Address:</strong> " + str(data_ip_address) + "</p>"
        + "<p><strong>Protocol:</strong> " + str(data_protocol) + "</p>"
        + "<p><strong>Port:</strong> " + str(data_port) + "</p>"
        + "<p><strong>Exploit?:</strong> " + str(data_exploit) + "</p>"
        + "<p><strong>MAC Address:</strong> " + str(data_mac_address) + "</p>"
        + "<p><strong>DNS Name:</strong> " + str(data_dns_name) + "</p>"
        + "<p><strong>NetBIOS Name:</strong> " + str(data_netbios_name) + "</p>"
        + "<p><strong>Plugin Output:</strong> " + str(data_plugin_output) + "</p>"
        + "<p><strong>First Discovered:</strong> " + str(data_first_discovered) + "</p>"
        + "<p><strong>Last Observed:</strong> " + str(data_last_observed) + "</p>"
        + "<p><strong>Exploit Frameworks:</strong> " + str(data_exploit_frameworks) + "</p>"
        + "<p><strong>Synopsis:</strong> " + str(data_synopsis) + "</p>"
        + "<p><strong>Description:</strong> " + str(data_description) + "</p>"
        + "<p><strong>Solution:</strong> " + str(data_solution) + "</p>"
        + "<p><strong>See Also:</strong> " + str(data_see_also) + "</p>"
        + "<p><strong>Risk Factor:</strong> " + str(data_risk_factor) + "</p>"
        + "<p><strong>STIG Severity:</strong> " + str(data_stig_severity) + "</p>"
        + "<p><strong>Vulnerability Priority Rating:</strong> " + str(data_vpr) + "</p>"
        + "<p><strong>CVSS V2 Base Score:</strong> " + str(data_cvss_v2_base) + "</p>"
        + "<p><strong>CVSS V3 Base Score:</strong> " + str(data_cvss_v3_base) + "</p>"
        + "<p><strong>CVSS V2 Temporal Score:</strong> " + str(data_cvss_v2_temporal) + "</p>"
        + "<p><strong>CVSS V3 Temporal Score:</strong> " + str(data_cvss_v3_temporal) + "</p>"
        + "<p><strong>CVSS V2 Vector:</strong> " + str(data_cvss_v2_vector) + "</p>"
        + "<p><strong>CVSS V3 Vector:</strong> " + str(data_cvss_v3_vector) + "</p>"
        + "<p><strong>CPE:</strong> " + str(data_cpe) + "</p>"
        + "<p><strong>CVE:</strong> " + str(data_cve) + "</p>"
        + "<p><strong>BID:</strong> " + str(data_bid) + "</p>"
        + "<p><strong>Cross References:</strong> " + str(data_cross_references) + "</p>"
        + "<p><strong>Vuln Publication Date:</strong> " + str(data_vuln_pub_date) + "</p>"
        + "<p><strong>Patch Publication Date:</strong> " + str(data_patch_pub_date) + "</p>"
        + "<p><strong>Plugin Publication Date:</strong> " + str(data_plugin_pub_date) + "</p>"
        + "<p><strong>Plugin Modification Date:</strong> " + str(data_plugin_mod_date) + "</p>"
        + "<p><strong>Exploit Ease:</strong> " + str(data_exploit_ease) + "</p>"
        + "<p><strong>Check Type:</strong> " + str(data_check_type) + "</p>"
        + "<p><strong>Version:</strong> " + str(data_version) + "</p>"
        + "<p><strong>Custom Id:</strong> " + str(data_custom_id) + "</p>"
    )

    def get_findings(self, filename: str, test: Test):
        # Read the CSV
        content = filename.read()
        delimiter = self.detect_delimiter(content)
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        csv.field_size_limit(int(sys.maxsize / 10))  # the request/resp are big
        reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)
        dupes = {}
        # Iterate over each line and create findings
        for row in reader:
            # title: Could come from "Name" or "Plugin Name"
            title = row.get("Name", row.get("Plugin Name", row.get("asset.name")))
            if title is None or title == "":
                continue
            # severity: Could come from "Severity" or "Risk"
            raw_severity = row.get("Risk", row.get("severity", ""))
            if raw_severity == "":
                raw_severity = row.get("Severity", "Info")
            # this could actually be a int, so try to convert
            # and swallow the exception if it's a string a move on
            with contextlib.suppress(ValueError):
                int_severity = int(raw_severity)
                raw_severity = int_severity
            # convert the severity to something dojo likes
            severity = self._convert_severity(raw_severity)
            # Other text fields
            description = self.get_description(row)
            mitigation = str(row.get("Solution", row.get("definition.solution", row.get("Steps to Remediate", "N/A"))))
            impact = row.get("Description", row.get("definition.description", "N/A"))
            references = row.get("See Also", row.get("definition.see_also", "N/A"))
            references += "\nTenable Plugin ID: " + row.get("Plugin", "N/A")
            references += "\nPlugin Publication Date: " + row.get("Plugin Publication Date", "N/A")
            references += "\nPlugin Modification Date: " + row.get("Plugin Modification Date", "N/A")
            # Determine if the current row has already been processed
            dupe_key = (
                severity
                + title
                + row.get("Host", row.get("asset.host_name", "No host"))
                + str(row.get("Port", row.get("asset.port", "No port")))
                + row.get("Synopsis", row.get("definition.synopsis", "No synopsis"))
            )
            # Finding has not been detected in the current report. Proceed with
            # parsing
            if dupe_key not in dupes:
                # Create the finding object
                find = Finding(
                    title=title,
                    test=test,
                    description=description,
                    severity=severity,
                    mitigation=mitigation,
                    impact=impact,
                    references=references,
                )

                # manage CVSS vector (only v3.x for now)
                cvss_vector = row.get("CVSS V3 Vector", "")
                if cvss_vector != "":
                    find.cvssv3 = CVSS3(
                        "CVSS:3.0/" + str(cvss_vector),
                    ).clean_vector(output_prefix=True)

                # Add CVSS score if present
                cvssv3 = row.get("CVSSv3", row.get("definition.cvss3.base_score", ""))
                if cvssv3 != "":
                    find.cvssv3_score = cvssv3
                # manage CPE data
                detected_cpe = self._format_cpe(str(row.get("CPE", row.get("definition.cpe", ""))))
                if detected_cpe:
                    # TODO: support more than one CPE in Nessus CSV parser
                    if len(detected_cpe) > 1:
                        LOGGER.debug(
                            "more than one CPE for a finding. NOT supported by Nessus CSV parser",
                        )
                    cpe_decoded = re.sub(r'[\n\r\t\\+]', '', str(detected_cpe[0]))
                    cpe_decoded = CPE(cpe_decoded)
                    find.component_name = (
                        cpe_decoded.get_product()[0]
                        if len(cpe_decoded.get_product()) > 0
                        else None
                    )
                    find.component_version = (
                        cpe_decoded.get_version()[0]
                        if len(cpe_decoded.get_version()) > 0
                        else None
                    )

                find.unsaved_endpoints = []
                find.unsaved_vulnerability_ids = []
                dupes[dupe_key] = find
            else:
                # This is a duplicate. Update the description of the original
                # finding
                find = dupes[dupe_key]

            # Determine if there is more details to be included in the
            # description
            plugin_output = str(row.get("Plugin Output", row.get("output", "")))
            if plugin_output != "":
                find.description += f"\n\n{plugin_output}"
            # Process any CVEs
            detected_cve = self._format_cve(str(row.get("CVE", row.get("definition.cve", ""))))
            if detected_cve:
                if isinstance(detected_cve, list):
                    find.unsaved_vulnerability_ids += detected_cve
                else:
                    find.unsaved_vulnerability_ids.append(detected_cve)
            # Endpoint related fields
            host = row.get("Host", row.get("asset.host_name", ""))
            if host == "":
                host = row.get("DNS Name", "")
            if host == "":
                host = row.get("IP Address", "localhost")

            protocol = row.get("Protocol", row.get("protocol", ""))
            protocol = protocol.lower() if protocol != "" else None
            port = str(row.get("Port", row.get("asset.port", "")))
            if isinstance(port, str) and port in ["", "0"]:
                port = None
            # Update the endpoints
            endpoint = Endpoint.from_uri(host) if "://" in host else Endpoint(protocol=protocol, host=host, port=port)
            # Add the list to be processed later
            find.unsaved_endpoints.append(endpoint)

        return list(dupes.values())
