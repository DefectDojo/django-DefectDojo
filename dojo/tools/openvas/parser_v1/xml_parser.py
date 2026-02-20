import contextlib
from xml.dom import NamespaceErr

from defusedxml import ElementTree
from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.protocol import LocationData

class OpenVASXMLParser:
    def get_findings(self, filename, test):
        findings = []
        tree = ElementTree.parse(filename)
        root = tree.getroot()
        if "report" not in root.tag:
            msg = "This doesn't seem to be a valid Greenbone OpenVAS XML file."
            raise NamespaceErr(msg)
        report = root.find("report")
        results = report.find("results")
        for result in results:
            script_id = None
            loc_host = ""
            loc_port = None
            loc_protocol = ""

            # TODO: Delete this after the move to Locations
            if not settings.V3_FEATURE_LOCATIONS:
                unsaved_endpoint = Endpoint()

            for field in result:
                if field.tag == "name":
                    title = field.text
                    description = [f"**Name**: {field.text}"]
                if field.tag == "hostname":
                    title = title + "_" + field.text
                    description.append(f"**Hostname**: {field.text}")
                    if field.text:
                        host_val = field.text.strip()  # strip due to https://github.com/greenbone/gvmd/issues/2378
                        loc_host = host_val
                        if not settings.V3_FEATURE_LOCATIONS:
                            unsaved_endpoint.host = host_val
                if field.tag == "host":
                    title = title + "_" + field.text
                    description.append(f"**Host**: {field.text}")
                    if not loc_host and field.text:
                        host_val = field.text.strip()  # strip due to https://github.com/greenbone/gvmd/issues/2378
                        loc_host = host_val
                        if not settings.V3_FEATURE_LOCATIONS and not unsaved_endpoint.host:
                            unsaved_endpoint.host = host_val
                if field.tag == "port":
                    title = title + "_" + field.text
                    description.append(f"**Port**: {field.text}")
                    if field.text:
                        port_str, protocol = field.text.split("/")
                        with contextlib.suppress(ValueError):
                            loc_port = int(port_str)
                            if not settings.V3_FEATURE_LOCATIONS:
                                unsaved_endpoint.port = loc_port
                        loc_protocol = protocol
                        if not settings.V3_FEATURE_LOCATIONS:
                            unsaved_endpoint.protocol = protocol
                if field.tag == "nvt":
                    description.append(f"**NVT**: {field.text}")
                    script_id = field.get("oid") or field.text
                if field.tag == "severity":
                    description.append(f"**Severity**: {field.text}")
                if field.tag == "threat":
                    description.append(f"**Threat**: {field.text}")
                    severity = field.text if field.text in {"Info", "Low", "Medium", "High", "Critical"} else "Info"
                if field.tag == "qod":
                    description.append(f"**QOD**: {field.text}")
                if field.tag == "description":
                    description.append(f"**Description**: {field.text}")

            finding = Finding(
                title=str(title),
                test=test,
                description="\n".join(description),
                severity=severity,
                dynamic_finding=True,
                static_finding=False,
                vuln_id_from_tool=script_id,
            )
            if settings.V3_FEATURE_LOCATIONS:
                finding.unsaved_locations = [LocationData.url_from_parts(
                    host=loc_host, port=loc_port, protocol=loc_protocol,
                )]
            else:
                # TODO: Delete this after the move to Locations
                finding.unsaved_endpoints = [unsaved_endpoint]
            findings.append(finding)
        return findings

    def convert_cvss_score(self, raw_value):
        val = float(raw_value)
        if val == 0:
            return "Info"
        if val < 4.0:
            return "Low"
        if val < 7.0:
            return "Medium"
        if val < 9.0:
            return "High"
        return "Critical"
