import hashlib
import json
import logging
from datetime import datetime

import dateutil
from defusedxml import ElementTree

from dojo.models import Endpoint, Finding

__author__ = "properam"
logger = logging.getLogger(__name__)


class ImmuniwebParser:
    def get_scan_types(self):
        return ["Immuniweb Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "XML or JSON Scan Result File from Imuniweb Scan."

    def get_findings(self, file, test):
        if file.name.lower().endswith(".xml"):
            return self.get_findings_from_xml(file, test)
        return self.get_findings_from_json(file, test)

    def get_findings_from_xml(self, file, test):
        ImmuniScanTree = ElementTree.parse(file)
        root = ImmuniScanTree.getroot()
        # validate XML file
        if "Vulnerabilities" not in root.tag:
            msg = "This does not look like a valid expected Immuniweb XML file."
            raise ValueError(msg)

        dupes = {}

        for vulnerability in root.iter("Vulnerability"):
            """
            The Tags available in XML File are:
            ID, Name, Date, Status,
            Type, CWE_ID, CVE_ID, CVSSv3,
            Risk, URL, Description, PoC
            """
            mitigation = "N/A"
            impact = "N/A"
            title = vulnerability.find("Name").text
            reference = vulnerability.find("ID").text
            cwe = "".join(
                i for i in vulnerability.find("CWE-ID").text if i.isdigit()
            )
            cwe = cwe or None
            vulnerability_id = vulnerability.find("CVE-ID").text
            steps_to_reproduce = vulnerability.find("PoC").text
            # just to make sure severity is in the recognised sentence casing
            # form
            severity = vulnerability.find("Risk").text.capitalize()
            # Set 'Warning' severity === 'Informational'
            if severity == "Warning":
                severity = "Informational"

            description = vulnerability.find("Description").text
            url = vulnerability.find("URL").text

            dupe_key = hashlib.md5(
                str(description + title + severity).encode("utf-8"),
            ).hexdigest()

            # check if finding is a duplicate
            if dupe_key in dupes:
                finding = dupes[dupe_key]  # fetch finding
                if description is not None:
                    finding.description += description
            else:  # finding is not a duplicate
                # create finding
                finding = Finding(
                    title=title,
                    test=test,
                    description=description,
                    severity=severity,
                    steps_to_reproduce=steps_to_reproduce,
                    cwe=cwe,
                    mitigation=mitigation,
                    impact=impact,
                    references=reference,
                    dynamic_finding=True,
                )
                if vulnerability_id:
                    finding.unsaved_vulnerability_ids = [vulnerability_id]
                finding.unsaved_endpoints = []
                dupes[dupe_key] = finding

                finding.unsaved_endpoints.append(Endpoint.from_uri(url))

        return list(dupes.values())

    def get_findings_from_json(self, file, test):
        findings = []

        root = json.load(file)

        for section in root:
            data = root.get(section)
            findings.extend(
                self.get_findings_from_domains_json(section, data, test),
            )

        return findings

    def get_findings_from_domains_json(self, section, data, test):
        findings = []
        for item in data:
            if not item.get("remediations", []):
                continue

            # the json contains different types of extra/context information
            title = item.get("type", "unknown") + ": " + item.get("name", "unknown")
            title += " - " + item["leak_name"] if item.get("leak_name") else ""
            date = dateutil.parser.parse(item["discovered"]) if item.get("discovered") else datetime.now()

            tag = item["tag"] if item.get("tag") else None
            endpoints = []
            if item.get("link", None):
                endpoints.append(Endpoint.from_uri(item["link"]) if "://" in item["link"] else Endpoint.from_uri("https://" + item["link"]))
            if item.get("ip", None):
                endpoints.append(Endpoint.from_uri(item["ip"]))

            # censor passwords in examples
            # this is a bit of a hack, but it's unclear what fields the json can contain
            if "examples" in item:
                for example in item["examples"]:
                    if "password" in example:
                        example["password"] = "REDACTED"  # noqa: S105

            remediations = item.get("remediations", [])

            for remediation in remediations:
                description = mitigation = remediation
                # the json contains different types of extra/context information
                # we just include everything in the description for now as it's unclear which fields are relevant
                description += "\n\n"
                description += " ## Details\n"
                description += "```\n"
                description += json.dumps(item, indent=4)
                description += "```\n"

                finding = Finding(
                    title=title,
                    test=test,
                    date=date,
                    description=description,
                    mitigation=mitigation,
                    severity="Informational",
                    dynamic_finding=True,
                )
                finding.unsaved_tags = [tag] if tag else None
                finding.unsaved_endpoints = endpoints

                findings.append(finding)
        return findings
