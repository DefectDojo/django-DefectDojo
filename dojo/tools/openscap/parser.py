import hashlib
import re

from defusedxml.ElementTree import parse
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv46_address

from dojo.models import Endpoint, Finding


class OpenscapParser:
    def get_scan_types(self):
        return ["Openscap Vulnerability Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import Openscap Vulnerability Scan in XML formats."

    def get_findings(self, file, test):
        tree = parse(file)
        # get root of tree.
        root = tree.getroot()
        namespace = self.get_namespace(root)

        # check if xml file hash correct root or not.
        if "Benchmark" not in root.tag:
            msg = "This doesn't seem to be a valid Openscap vulnerability scan xml file."
            raise ValueError(msg)
        if "http://checklists.nist.gov/xccdf/" not in namespace:
            msg = "This doesn't seem to be a valid Openscap vulnerability scan xml file."
            raise ValueError(msg)

        # read rules
        rules = {}
        for rule in root.findall(f".//{namespace}Rule"):
            rules[rule.attrib["id"]] = {
                "title": rule.findtext(f"./{namespace}title"),
            }
        # go to test result
        test_result = tree.find(f"./{namespace}TestResult")
        ips = [ip.text for ip in test_result.findall(f"./{namespace}target")] \
              + [ip.text for ip in test_result.findall(f"./{namespace}target-address")]

        dupes = {}
        # run both rule, and rule-result in parallel so that we can get title
        # for failed test from rule.
        for rule_result in test_result.findall(
            f"./{namespace}rule-result",
        ):
            result = rule_result.findtext(f"./{namespace}result")
            # find only failed report.
            if "fail" in result:
                # get rule corresponding to rule-result
                rule = rules[rule_result.attrib["idref"]]
                title = rule["title"]
                description = "\n".join(
                    [
                        "**IdRef:** `" + rule_result.attrib["idref"] + "`",
                        "**Title:** `" + title + "`",
                    ],
                )
                vulnerability_ids = [vulnerability_id.text
                    for vulnerability_id in rule_result.findall(f"./{namespace}ident[@system='http://cve.mitre.org']")]
                # get severity.
                severity = (
                    rule_result.attrib.get("severity", "medium")
                    .lower()
                    .capitalize()
                )
                # according to the spec 'unknown' is a possible value
                if severity == "Unknown":
                    severity = "Info"
                references = ""
                # get references.
                for check_content in rule_result.findall(
                    f"./{namespace}check/{namespace}check-content-ref",
                ):
                    references += (
                        "**name:** : " + check_content.attrib["name"] + "\n"
                    )
                    references += (
                        "**href** : " + check_content.attrib["href"] + "\n"
                    )

                finding = Finding(
                    title=title,
                    description=description,
                    severity=severity,
                    references=references,
                    dynamic_finding=True,
                    static_finding=False,
                    unique_id_from_tool=rule_result.attrib["idref"],
                )
                if vulnerability_ids:
                    finding.unsaved_vulnerability_ids = vulnerability_ids
                finding.unsaved_endpoints = []
                for ip in ips:
                    try:
                        validate_ipv46_address(ip)
                        endpoint = Endpoint(host=ip)
                    except ValidationError:
                        if "://" in ip:
                            endpoint = Endpoint.from_uri(ip)
                        else:
                            endpoint = Endpoint.from_uri("//" + ip)
                    finding.unsaved_endpoints.append(endpoint)

                dupe_key = hashlib.sha256(
                    references.encode("utf-8"),
                ).hexdigest()
                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    if finding.references:
                        find.references = finding.references
                    find.unsaved_endpoints.extend(finding.unsaved_endpoints)
                else:
                    dupes[dupe_key] = finding

        return list(dupes.values())

    def get_namespace(self, element):
        """Extract namespace present in XML file."""
        m = re.match(r"\{.*\}", element.tag)
        return m.group(0) if m else ""
