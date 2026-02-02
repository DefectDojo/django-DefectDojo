import hashlib
import json
from datetime import datetime

from cpe import CPE
from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.url.models import URL


class TrustwaveFusionAPIParser:

    """Import Trustwave Fusion Report from its API in JSON format"""

    def get_scan_types(self):
        return ["Trustwave Fusion API Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Trustwave Fusion API Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Trustwave Fusion API report file can be imported in JSON format"
        )

    def get_findings(self, file, test):
        tree = json.load(file)
        items = {}

        # iterating through each vulnerability
        for node in tree["items"]:
            item = get_item(node, test)

            item_key = hashlib.sha256(
                f"{item.severity}|{item.title}|{item.description}".encode(),
            ).hexdigest()

            if item_key in items:
                if settings.V3_FEATURE_LOCATIONS:
                    items[item_key].unsaved_locations.extend(
                        item.unsaved_locations,
                    )
                else:
                    # TODO: Delete this after the move to Locations
                    items[item_key].unsaved_endpoints.extend(
                        item.unsaved_endpoints,
                    )
                items[item_key].nb_occurences += 1
            else:
                items[item_key] = item

        return list(items.values())

    def convert_severity(self, num_severity):
        """Convert severity value"""
        if num_severity >= -10:
            return "Low"
        if -11 >= num_severity > -26:
            return "Medium"
        if num_severity <= -26:
            return "High"
        return "Info"


def extract_location(finding, location_data):
    if settings.V3_FEATURE_LOCATIONS:
        # Location
        #  using url
        if "url" in location_data and location_data["url"] and location_data["url"] != "None":
            location = URL.from_value(location_data["url"])
        # fallback to using old way of creating endpoints
        elif (
            "domain" in location_data
            and location_data["domain"]
            and location_data["domain"] != "None"
        ):
            location = URL(host=str(location_data["domain"]))
        elif "ip" in location_data and location_data["ip"] and location_data["ip"] != "None":
            location = URL(host=str(location_data["ip"]))
        else:
            # No host, which is required for URLs
            return
        # check for protocol
        if (
            "applicationProtocol" in location_data
            and location_data["applicationProtocol"]
            and location_data["applicationProtocol"] != "None"
        ):
            location.protocol = location_data["applicationProtocol"]
        # check for port
        if (
            "port" in location_data
            and location_data["port"] in location_data
            and location_data["port"] != "None"
        ):
            location.port = location_data["port"]
        finding.unsaved_locations = [location]
    else:
        # TODO: Delete this after the move to Locations
        # Endpoint
        #  using url
        if "url" in location_data and location_data["url"] and location_data["url"] != "None":
            endpoint = Endpoint.from_uri(location_data["url"])
        # fallback to using old way of creating endpoints
        elif (
            "domain" in location_data
            and location_data["domain"]
            and location_data["domain"] != "None"
        ):
            endpoint = Endpoint(host=str(location_data["domain"]))
        elif "ip" in location_data and location_data["ip"] and location_data["ip"] != "None":
            endpoint = Endpoint(host=str(location_data["ip"]))
        # check for protocol
        if (
            "applicationProtocol" in location_data
            and location_data["applicationProtocol"]
            and location_data["applicationProtocol"] != "None"
        ):
            endpoint.protocol = location_data["applicationProtocol"]
        # check for port
        if (
            "port" in location_data
            and location_data["port"] in location_data
            and location_data["port"] != "None"
        ):
            endpoint.port = location_data["port"]
        finding.unsaved_endpoints = [endpoint]  # assigning endpoint


def get_item(vuln, test):
    finding = Finding(
        test=test,
        unique_id_from_tool=vuln["id"],
        nb_occurences=1,
    )

    # Defining variables
    location_data = vuln["location"]

    extract_location(finding, location_data)

    # Title
    finding.title = vuln["name"]

    # Description + CVEs
    description = vuln["classification"]
    cves = "no match"
    if "CVE-NO-MATCH" not in vuln["kb"]["cves"]:
        finding.unsaved_vulnerability_ids = vuln["kb"]["cves"]
        cves = ""
        for cve in vuln["kb"]["cves"]:
            cves += f"{cve}, "
        cves = cves[: len(cves) - 2]  # removing the comma and the blank space

    finding.description = description
    finding.severity = vuln["severity"].title()

    # Date
    date_str = vuln["createdOn"]
    date_str = date_str[: len(date_str) - 3] + date_str[-2:]
    finding.date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f%z")

    # Component Name and Version
    if (
        "applicationCpe" in location_data
        and location_data["applicationCpe"]
        and location_data["applicationCpe"] != "None"
    ):
        cpe = CPE(location_data["applicationCpe"])

        component_name = (
            cpe.get_vendor()[0] + ":" if len(cpe.get_vendor()) > 0 else ""
        )

        component_name += (
            cpe.get_product()[0] if len(cpe.get_product()) > 0 else ""
        )

        finding.component_name = component_name or None
        finding.component_version = (
            cpe.get_version()[0] if len(cpe.get_version()) > 0 else None
        )

    return finding
