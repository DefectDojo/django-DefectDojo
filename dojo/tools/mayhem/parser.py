import json
import logging
import re

import dateutil.parser
from django.utils.translation import gettext as _

from dojo.models import Finding
from dojo.tools.parser_test import ParserTest

from dojo.tools.sarif.parser import SarifParser
from dojo.tools.sarif.parser import (
    get_codeFlowsDescription,
    get_snippet,
    get_title,
    get_severity,
    get_references,
    cve_try,
    get_rule_cwes,
    get_result_cwes_properties,
    cvss_to_severity,
    get_properties_tags,
    get_fingerprints_hashes,
    get_rules
    )


logger = logging.getLogger(__name__)

CWE_REGEX = r"cwe-\d+"


class MayhemParser(SarifParser):
    """
    Mayhem SARIF Parser
    This class extends the existing SARIF parser, but with some minor
    modifications to better support the structure of Mayhem SARIF reports.
    """

    def get_scan_types(self):
        return ["Mayhem SARIF Report"]

    def get_description_for_scan_types(self):
        return "Mayhem SARIF reports from code or API runs."

    # Due to mixing of class methods and package functions, we need to override some of these methods
    # without changing their behavior. __get_items_from_run is name mangled in the parent class,
    # so inherited methods cannot access the version here in MayhemParser.
    def get_findings(self, filehandle, test):
        """For simple interface of parser contract we just aggregate everything"""
        tree = json.load(filehandle)
        items = []
        # for each runs we just aggregate everything
        for run in tree.get("runs", []):
            items.extend(self.__get_items_from_run(run))
        return items

    def get_tests(self, scan_type, handle):
        tree = json.load(handle)
        tests = []
        for run in tree.get("runs", []):
            test = ParserTest(
                name=run["tool"]["driver"]["name"],
                parser_type=run["tool"]["driver"]["name"],
                version=run["tool"]["driver"].get("version"),
            )
            test.findings = self.__get_items_from_run(run)
            tests.append(test)
        return tests

    def __get_items_from_run(self, run):
        items = []
        # load rules
        rules = get_rules(run)
        # Artifacts do not appear to be used anywhere
        # artifacts = get_artifacts(run)
        # get the timestamp of the run if possible
        run_date = self.__get_last_invocation_date(run)
        for result in run.get("results", []):
            result_items = get_items_from_result(result, rules, run_date)
            if result_items:
                items.extend(result_items)
        return items
    
    def __get_last_invocation_date(self, data):
        invocations = data.get("invocations", [])
        if len(invocations) == 0:
            return None
        # try to get the last 'endTimeUtc'
        raw_date = invocations[-1].get("endTimeUtc")
        if raw_date is None:
            return None
        # if the data is here we try to convert it to datetime
        return dateutil.parser.isoparse(raw_date)


def get_result_cwes_mcode(result):
    """Mayhem SARIF reports include CWE property under taxa.toolComponent.name and number under taxa.id"""
    cwes = []
    if "taxa" in result:
        for taxon in result["taxa"]:
            if taxon.get("toolComponent", {}).get("name") == "CWE":
                value = taxon.get("id")
                if value:
                    cwes.append(int(value))
    return cwes


def clean_mayhem_title_text(text):
    """Clean the title text for Mayhem SARIF reports."""
    if not text:
        return ""

    # Remove links (and add limit to avoid catastrophic backtracking)
    link_regex = r"\[[^\]]{1,100}?\]\([^)]{1,200}?\)"
    text = re.sub(link_regex, "", text)

    # Remove URL encoded characters
    url_encoding_regex = r"&#x\d+;"
    text = re.sub(url_encoding_regex, "", text)

    # Remove single or double quotes
    quotes_regex = r"[\"']"
    text = re.sub(quotes_regex, "", text)

    # Remove TDID
    tdid_regex = r"TDID-\d+\s*-\s*|TDID-\d+-"
    text = re.sub(tdid_regex, "", text)

    return text.strip()


def get_message_from_multiformatMessageString(data, rule, content_type="text"):
    """
    Get a message from multimessage struct

    Differs from Sarif implementation in that it handles markdown, specifies content_type
    """
    if content_type == "markdown" and "markdown" in data:
        # handle markdown content
        markdown = data.get("markdown")
        # strip "headings" or anything that changes text size
        heading_regex = r"^#+\s*"
        markdown = re.sub(heading_regex, "", markdown, flags=re.MULTILINE)
        # replace non-unicode characters with "?"
        non_unicode_regex = r"[^\x09\x0A\x0D\x20-\x7E]"
        markdown = re.sub(non_unicode_regex, "?", markdown)
        return markdown.strip()
    if content_type == "text" and "text" in data:
        # handle text content
        text = data.get("text")
        if rule is not None and "id" in data:
            text = rule["messageStrings"][data["id"]].get("text")
            arguments = data.get("arguments", [])
            # argument substitution
            for i in range(6):  # the specification limit to 6
                substitution_str = "{" + str(i) + "}"
                if substitution_str in text and i < len(arguments):
                    text = text.replace(substitution_str, arguments[i])
        return text
    return ""


def get_description(result, rule, location):
    """Overwrite the SarifParser get_description to handle markdown"""
    description = ""
    message = ""
    if "message" in result:
        message = get_message_from_multiformatMessageString(
            result["message"], rule,
        )
        description += f"**Result message:** {message}\n"
    if get_snippet(location) is not None:
        description += f"**Snippet:**\n```\n{get_snippet(location)}\n```\n"
    if rule is not None:
        if "name" in rule:
            description += f"**{_('Rule name')}:** {rule.get('name')}\n"
        shortDescription = ""
        if "shortDescription" in rule:
            shortDescription = get_message_from_multiformatMessageString(
                rule["shortDescription"], rule,
            )
            if shortDescription != message:
                description += f"**{_('Rule short description')}:** {shortDescription}\n"
        if "fullDescription" in rule:
            fullDescription = get_message_from_multiformatMessageString(
                rule["fullDescription"], rule,
            )
            if (fullDescription != message) and (fullDescription != shortDescription):
                description += f"**{_('Rule full description')}:** {fullDescription}\n"
    if "markdown" in result["message"]:
        markdown = get_message_from_multiformatMessageString(
            result["message"], rule, content_type="markdown",
        )
        # Replace "Details" with "Link" in the markdown
        markdown = markdown.replace("Details", "Link")
        description += f"**{_('Additional Details')}:**\n{markdown}\n"
        description += "_(Unprintable characters are replaced with '?'; please see Mayhem for full reproducer.)_"
    if len(result.get("codeFlows", [])) > 0:
        description += get_codeFlowsDescription(result["codeFlows"])

    return description.removesuffix("\n")


def get_items_from_result(result, rules, run_date):
    # see
    # https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html
    # / 3.27.9
    kind = result.get("kind", "fail")
    if kind != "fail":
        return None

    # if finding is suppressed, mark it as False Positive
    # Note: see
    # https://docs.oasis-open.org/sarif/sarif/v2.0/csprd02/sarif-v2.0-csprd02.html#_Toc10127852
    suppressed = False
    if result.get("suppressions"):
        suppressed = True

    # if there is a location get all files into files list

    files = []

    if "locations" in result:
        for location in result["locations"]:

            file_path = None
            line = None

            if "physicalLocation" in location:
                file_path = location["physicalLocation"]["artifactLocation"]["uri"]

                # 'region' attribute is optionnal
                if "region" in location["physicalLocation"]:
                    # https://docs.oasis-open.org/sarif/sarif/v2.0/csprd02/sarif-v2.0-csprd02.html / 3.30.1
                    # need to check whether it is byteOffset
                    if "byteOffset" in location["physicalLocation"]["region"]:
                        pass
                    else:
                        line = location["physicalLocation"]["region"]["startLine"]

            files.append((file_path, line, location))

    if not files:
        files.append((None, None, None))

    result_items = []

    for file_path, line, location in files:

        # test rule link
        rule = rules.get(result.get("ruleId"))

        finding = Finding(
            title=clean_mayhem_title_text(get_title(result, rule)),
            severity=get_severity(result, rule),
            description=get_description(result, rule, location),
            static_finding=False,
            dynamic_finding=True,
            false_p=suppressed,
            active=not suppressed,
            file_path=file_path,
            line=line,
            references=get_references(rule),
        )

        if "ruleId" in result:
            finding.vuln_id_from_tool = result["ruleId"]
            # for now we only support when the id of the rule is a CVE
            if cve_try(result["ruleId"]):
                finding.unsaved_vulnerability_ids = [cve_try(result["ruleId"])]
        # some time the rule id is here but the tool doesn't define it
        if rule is not None:
            cwes_extracted = get_rule_cwes(rule)
            # Find CWEs in Mayhem SARIF reports
            cwes_extracted.extend(get_result_cwes_mcode(result))
            if len(cwes_extracted) > 0:
                finding.cwe = cwes_extracted[-1]

            # Some tools such as GitHub or Grype return the severity in properties
            # instead
            if "properties" in rule and "security-severity" in rule["properties"]:
                try:
                    cvss = float(rule["properties"]["security-severity"])
                    severity = cvss_to_severity(cvss)
                    finding.cvssv3_score = cvss
                    finding.severity = severity
                except ValueError:
                    if rule["properties"]["security-severity"].lower().capitalize() in {"Info", "Low", "Medium", "High", "Critical"}:
                        finding.severity = rule["properties"]["security-severity"].lower().capitalize()
                    else:
                        finding.severity = "Info"

        # manage the case that some tools produce CWE as properties of the result
        cwes_properties_extracted = get_result_cwes_properties(result)
        if len(cwes_properties_extracted) > 0:
            finding.cwe = cwes_properties_extracted[-1]

        # manage fixes provided in the report
        if "fixes" in result:
            finding.mitigation = "\n".join(
                [fix.get("description", {}).get("text") for fix in result["fixes"]],
            )

        if run_date:
            finding.date = run_date

        # manage tags provided in the report and rule and remove duplicated
        tags = list(set(get_properties_tags(rule) + get_properties_tags(result)))
        tags = [s.removeprefix("external/cwe/") for s in tags]
        finding.tags = tags

        # manage fingerprints
        # fingerprinting in SARIF is more complete than in current implementation
        # SARIF standard make it possible to have multiple version in the same report
        # for now we just take the first one and keep the format to be able to
        # compare it
        if result.get("fingerprints"):
            hashes = get_fingerprints_hashes(result["fingerprints"])
            first_item = next(iter(hashes.items()))
            finding.unique_id_from_tool = first_item[1]["value"]
        elif result.get("partialFingerprints"):
            # for this one we keep an order to have id that could be compared
            hashes = get_fingerprints_hashes(result["partialFingerprints"])
            sorted_hashes = sorted(hashes.keys())
            finding.unique_id_from_tool = "|".join(
                [f'{key}:{hashes[key]["value"]}' for key in sorted_hashes],
            )

        result_items.append(finding)

    return result_items
