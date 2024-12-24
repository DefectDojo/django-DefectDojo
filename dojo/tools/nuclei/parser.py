import hashlib
import json
import logging

from cvss import parser as cvss_parser
from dateutil import parser as date_parser

from dojo.models import Endpoint, Finding, Problem
import dojo.problem.helper as problems_help

logger = logging.getLogger(__name__)


class NucleiParser:

    """A class that can be used to parse the nuclei (https://github.com/projectdiscovery/nuclei) JSON report file"""

    DEFAULT_SEVERITY = "Low"

    def get_scan_types(self):
        return ["Nuclei Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Nuclei Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON output for nuclei scan report."

    def get_findings(self, filename, test):
        filecontent = filename.read()
        if isinstance(filecontent, bytes):
            filecontent = filecontent.decode("utf-8")
        data = []
        if filecontent == "" or len(filecontent) == 0:
            return []
        if filecontent[0] == "[":
            content = json.loads(filecontent)
            for template in content:
                data.append(template)
        elif filecontent[0] == "{":
            file = filecontent.split("\n")
            for line in file:
                if line != "":
                    data.append(json.loads(line))
        dupes = {}
        script_to_problem_mapping = problems_help.load_json()
        for item in data:
            logger.debug("Item %s.", str(item))
            template_id = item.get("templateID", item.get("template-id", ""))
            info = item.get("info")
            name = info.get("name")
            severity = info.get("severity").title()
            if severity not in Finding.SEVERITIES:
                logger.debug(
                    'Unsupported severity value "%s", change to "%s"',
                    severity,
                    self.DEFAULT_SEVERITY,
                )
                severity = self.DEFAULT_SEVERITY
            item_type = item.get("type")
            if item_type is None:
                item_type = ""
            matched = item.get("matched", item.get("matched-at", ""))
            endpoint = Endpoint.from_uri(matched) if "://" in matched else Endpoint.from_uri("//" + matched)

            finding = Finding(
                title=f"{name}",
                test=test,
                severity=severity,
                nb_occurences=1,
                vuln_id_from_tool=template_id,
            )
            if finding.severity != "Info" and finding.vuln_id_from_tool:
                finding.problem = problems_help.find_or_create_problem(finding, script_to_problem_mapping)
                finding.save()
            if item.get("timestamp"):
                finding.date = date_parser.parse(item.get("timestamp"))
            if info.get("description"):
                finding.description = info.get("description")
            if item.get("extracted-results"):
                finding.description += "\n**Results:**\n" + "\n".join(
                    item.get("extracted-results"),
                )
            if info.get("tags"):
                finding.unsaved_tags = info.get("tags")
            if info.get("reference"):
                reference = info.get("reference")
                if isinstance(reference, list):
                    finding.references = "\n".join(info.get("reference"))
                else:
                    finding.references = info.get("reference")

            finding.unsaved_endpoints.append(endpoint)

            classification = info.get("classification")
            if classification:
                if classification.get("cve-id"):
                    cve_ids = classification["cve-id"]
                    finding.unsaved_vulnerability_ids = [x.upper() for x in cve_ids]
                if (
                    classification.get("cwe-id")
                ):
                    cwe = classification["cwe-id"][0]
                    try:
                        finding.cwe = int(cwe[4:])
                    except ValueError:
                        """
                        ignore CWE if non-int
                        several older templates such as https://github.com/projectdiscovery/nuclei-templates/blob/6636c0d2dd540645cc3472822beb4b3819ff8322/http/cves/2004/CVE-2004-0519.yaml#L21
                        """
                if classification.get("cvss-metrics"):
                    cvss_objects = cvss_parser.parse_cvss_from_text(
                        classification["cvss-metrics"],
                    )
                    if len(cvss_objects) > 0:
                        finding.cvssv3 = cvss_objects[0].clean_vector()
                if classification.get("cvss-score"):
                    finding.cvssv3_score = classification["cvss-score"]

            matcher = item.get("matcher-name", item.get("matcher_name"))
            if matcher:
                finding.component_name = matcher
            else:
                matcher = ""

            if info.get("remediation"):
                finding.mitigation = info.get("remediation")

            host = item.get("host", "")

            if item.get("curl-command"):
                finding.steps_to_reproduce = (
                    "curl command to reproduce the request:\n`"
                    + item.get("curl-command")
                    + "`"
                )

            if item.get("request"):
                finding.unsaved_request = item.get("request")
            if item.get("response"):
                finding.unsaved_response = item.get("response")

            logger.debug(
                "dupe keys %s, %s, %s, %s.",
                template_id,
                item_type,
                matcher,
                host,
            )

            dupe_key = hashlib.sha256(
                (template_id + item_type + matcher + endpoint.host).encode(
                    "utf-8",
                ),
            ).hexdigest()

            if dupe_key in dupes:
                logger.debug("dupe_key %s exists.", str(dupe_key))
                finding = dupes[dupe_key]
                if endpoint not in finding.unsaved_endpoints:
                    finding.unsaved_endpoints.append(endpoint)
                    logger.debug("Appended endpoint %s", endpoint)
                finding.nb_occurences += 1
            else:
                dupes[dupe_key] = finding
        return list(dupes.values())
