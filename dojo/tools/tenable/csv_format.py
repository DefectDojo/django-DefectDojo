import csv
import io
import logging
import re
import sys

from cpe import CPE
from cvss import CVSS3

from dojo.models import Endpoint, Finding, Test

LOGGER = logging.getLogger(__name__)


class TenableCSVParser(object):

    def _convert_severity(self, val):
        if val is None or len(val) == 0:
            return "Info"
        severity = val.title()
        # Ensure the severity is a valid choice. Fall back to info otherwise
        if severity not in Finding.SEVERITIES.keys():
            severity = "Info"
        return severity

    def _format_cve(self, val):
        if val is None or val == "":
            return None
        cve_match = re.findall(r"CVE-[0-9]+-[0-9]+", val.upper(), re.IGNORECASE)
        if cve_match:
            return cve_match
        return None

    def _format_cpe(self, val):
        if val is None or val == "":
            return None
        cpe_match = re.findall(r"cpe:/[^\n\ ]+", val)
        return cpe_match if cpe_match else None

    def get_findings(self, filename: str, test: Test):
        # Read the CSV
        content = filename.read()
        if type(content) is bytes:
            content = content.decode("utf-8")
        csv.field_size_limit(int(sys.maxsize / 10))  # the request/resp are big
        reader = csv.DictReader(io.StringIO(content))
        dupes = {}
        # Iterate over each line and create findings
        for row in reader:
            # title: Could come from "Name" or "Plugin Name"
            title = row.get("Name", row.get("Plugin Name"))
            if title is None or title == "":
                continue
            # Severity: Could come from "Severity" or "Risk"
            raw_severity = row.get("Severity", row.get("Risk", "Info"))
            severity = self._convert_severity(raw_severity)
            # Other text fields
            description = row.get("Synopsis", "")
            mitigation = str(row.get("Solution", "N/A"))
            impact = row.get("Description", "N/A")
            references = row.get("See Also", "N/A")
            # Determine if the current row has already been processed
            dupe_key = severity + title + row.get('Host', 'No host') + str(row.get('Port', 'No port')) + row.get('Synopsis', 'No synopsis')

            # Finding has not been detected in the current report. Proceed with parsing
            if dupe_key not in dupes:
                # Create the finding object
                find = Finding(
                    title=title,
                    test=test,
                    description=description,
                    severity=severity,
                    mitigation=mitigation,
                    impact=impact,
                    references=references
                )

                # manage CVSS vector (only v3.x for now)
                cvss_vector = row.get("CVSS V3 Vector", "")
                if cvss_vector != "":
                    find.cvssv3 = CVSS3("CVSS:3.0/" + str(cvss_vector)).clean_vector(output_prefix=True)

                # Add CVSS score if present
                cvssv3 = row.get('CVSSv3', "")
                if cvssv3 != "":
                    find.cvssv3_score = cvssv3
                # manage CPE data
                detected_cpe = self._format_cpe(str(row.get("CPE", "")))
                if detected_cpe:
                    # FIXME support more than one CPE in Nessus CSV parser
                    if len(detected_cpe) > 1:
                        LOGGER.debug("more than one CPE for a finding. NOT supported by Nessus CSV parser")
                    cpe_decoded = CPE(detected_cpe[0])
                    find.component_name = cpe_decoded.get_product()[0] if len(cpe_decoded.get_product()) > 0 else None
                    find.component_version = cpe_decoded.get_version()[0] if len(cpe_decoded.get_version()) > 0 else None

                find.unsaved_endpoints = []
                find.unsaved_vulnerability_ids = []
                dupes[dupe_key] = find
            else:
                # This is a duplicate. Update the description of the original finding
                find = dupes[dupe_key]

            # Determine if there is more details to be included in the description
            plugin_output = str(row.get("Plugin Output", ""))
            if plugin_output != "":
                find.description += f"\n\n{plugin_output}"
            # Process any CVEs
            detected_cve = self._format_cve(str(row.get("CVE", "")))
            if detected_cve:
                if isinstance(detected_cve, list):
                    find.unsaved_vulnerability_ids += detected_cve
                else:
                    find.unsaved_vulnerability_ids.append(detected_cve)
            # Endpont related fields
            host = row.get("Host", "")
            if host == "":
                host = row.get("DNS Name", "")
            if host == "":
                host = row.get("IP Address", "localhost")

            protocol = row.get("Protocol", "")
            protocol = protocol.lower() if protocol != "" else None
            port = row.get("Port", "")
            if isinstance(port, str) and port == "":
                port = None
            # Update the endpoints
            if '://' in host:
                endpoint = Endpoint.from_uri(host)
            else:
                endpoint = Endpoint(
                    protocol=protocol,
                    host=host,
                    port=port)
            # Add the list to be processed later
            find.unsaved_endpoints.append(endpoint)

        return list(dupes.values())
