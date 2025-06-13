import hashlib
import re
import html2text
import defusedxml.ElementTree as ElementTree

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
        tree = ElementTree.parse(file)
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
            # get description and rationale (contains html codes)
            desc_elem = rule.find(f"./{namespace}description")
            rationale_elem = rule.find(f"./{namespace}rationale")
            description_html = ElementTree.tostring(desc_elem, encoding="unicode", method="xml") if desc_elem is not None else "none"
            rationale_html = ElementTree.tostring(rationale_elem, encoding="unicode", method="xml") if rationale_elem is not None else "none"
            # remove xml-html namespace
            description_html = re.sub(r"</?html:(\w+)", r"<\1", description_html)
            rationale_html = re.sub(r"</?html:(\w+)", r"<\1", rationale_html)
            # remove newlines (DefectDojo already breaks lines)
            description_html = re.sub(r"[\r\n]+", " ", description_html)
            rationale_html = re.sub(r"[\r\n]+", " ", rationale_html)

            rules[rule.attrib["id"]] = {
                "title": rule.findtext(f"./{namespace}title"),
                "description": html2text.html2text(description_html),
                "rationale": html2text.html2text(rationale_html),
            }
        # go to test result
        test_result = tree.find(f"./{namespace}TestResult")
        # append all target in a list.
        ips = [ip.text for ip in test_result.findall(f"./{namespace}target")]
        ips.extend(ip.text for ip in test_result.findall(f"./{namespace}target-address"))

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
                ruleid = rule_result.attrib["idref"]
                rule = rules[ruleid]
                title = rule["title"]
                desc = rule["description"]
                rat = rule["rationale"]
                description = "\n".join(
                    [
                        "**IdRef:** `" + ruleid + "`",
                        "**Title:** `" + title + "`",
                        "**Description:** ",
                        desc,
                        "**Rationale:** ",
                        rat,
                    ],
                )
                vulnerability_ids = [vulnerability_id.text for vulnerability_id in rule_result.findall(
                    f"./{namespace}ident[@system='http://cve.mitre.org']",
                )]
                # get severity.
                severity = (
                    rule_result.attrib.get("severity", "medium")
                    .lower()
                    .capitalize()
                )
                # according to the spec 'unknown' is a possible value
                if severity == "Unknown":
                    severity = "Info"
                # get references.
                for check_content in rule_result.findall(
                    f"./{namespace}check/{namespace}check-content-ref",
                ):
                    references = "\n".join(
                        [
                            "**name:** : " + check_content.attrib["name"],
                            "**href** : " + check_content.attrib["href"],
                        ],
                    )

                finding = Finding(
                    title=title,
                    description=description,
                    severity=severity,
                    references=references,
                    dynamic_finding=True,
                    static_finding=False,
                    unique_id_from_tool=ruleid,
                )
                if vulnerability_ids:
                    finding.unsaved_vulnerability_ids = vulnerability_ids
                finding.unsaved_endpoints = []
                for ip in ips:
                    try:
                        validate_ipv46_address(ip)
                        endpoint = Endpoint(host=ip)
                    except ValidationError:
                        endpoint = Endpoint.from_uri(ip) if "://" in ip else Endpoint.from_uri("//" + ip)
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
