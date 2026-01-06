import json
import logging
import re
import textwrap

import dateutil.parser
from django.utils.translation import gettext as _

from dojo.models import Finding
from dojo.tools.parser_test import ParserTest

logger = logging.getLogger(__name__)

CWE_REGEX = r"cwe-\d+"


class SarifParser:

    """
    OASIS Static Analysis Results Interchange Format (SARIF) for version 2.1.0 only.

    https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif
    """

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Sarif Parser

        Fields:
        - title: Made using rule and id from Sarif scanner.
        - severity: Set to severity from Sarif Scanner converted to Defect Dojo format.
        - description: Made by combining message, location, and rule from Sarif Scanner.
        - static_finding: Set to true.
        - dynamic_finding: Set to false.
        - false_p: Set to true or false based on suppression status from Sarif scanner.
        - active: Set to true or false based on suppression status from Sarif scanner.
        - file_path: Set to physical location from Sarif scanner.
        - line: Set to start line from Sarif scanner.
        - vuln_id_from_tool: Set to rule id from Sarif scanner.
        - cwe: Set to the cwe values outputted from Sarif Scanner.
        - cvssv3: Set to properties and securitiy-severity from Sarif scanner if available.
        - cvssv3_score: Set to properties and securitiy-severity from Sarif scanner if available.
        - mitigation: Set to altered version of finding's description.
        - date: Set to the date outputted from Sarif Scanner converted to datetime.
        - tags: Set to tags from Sarif scanner.
        - unique_id_from_tool: Set to the hash fingerpring value outputted from Sarif Scanner.

        NOTE: This parser supports tags.
        """
        return [
            "title",
            "severity",
            "description",
            "static_finding",
            "dynamic_finding",
            "false_p",
            "active",
            "file_path",
            "line",
            "vuln_id_from_tool",
            "cwe",
            "cvssv3",
            "cvssv3_score",
            "mitigation",
            "date",
            "tags",
            "unique_id_from_tool",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of dedupe fields used in the Sarif Parser

        Fields:
        - title: Made using rule and id from Sarif scanner.
        - cwe: Set to the cwe values outputted from Sarif Scanner.
        - line: Set to start line from Sarif scanner.
        - file_path: Set to physical location from Sarif scanner.
        - description: Made by combining message, location, and rule from Sarif Scanner.

        NOTE: uses legacy dedupe: ['title', 'cwe', 'line', 'file_path', 'description']
        """
        return [
            "title",
            "cwe",
            "line",
            "file_path",
            "description",
        ]

    def get_scan_types(self):
        return ["SARIF"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "SARIF report file can be imported in SARIF format."

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
        artifacts = get_artifacts(run)
        # get the timestamp of the run if possible
        run_date = self.__get_last_invocation_date(run)
        for result in run.get("results", []):
            result_items = self.get_items_from_result(result, rules, artifacts, run_date)
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

    # Extension points for subclasses
    def get_items_from_result(self, result, rules, artifacts, run_date):
        """
        Main method to extract findings from a SARIF result.
        This method can be overridden by subclasses for custom behavior.
        """
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

            # Get description from parser (uses inheritance)
            description = self.get_finding_description(result, rule, location)

            # Get title from parser (uses inheritance)
            title = self.get_finding_title(result, rule, location)

            # Get finding type (uses inheritance)
            static_finding, dynamic_finding = self.get_finding_type()

            finding = Finding(
                title=title,
                severity=get_severity(result, rule),
                description=description,
                static_finding=static_finding,
                dynamic_finding=dynamic_finding,
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

            # manage the case that some tools produce CWE using taxa (official SARIF approach)
            cwes_taxa_extracted = get_result_cwes_taxa(result)
            if len(cwes_taxa_extracted) > 0:
                finding.cwe = cwes_taxa_extracted[-1]

            # Get custom CWEs if available (uses inheritance)
            custom_cwes = self.get_finding_cwes(result)
            if custom_cwes:
                finding.cwe = custom_cwes[-1]  # Use the last CWE like other logic

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

            # Allow subclasses to customize the finding (uses inheritance)
            self.customize_finding(finding, result, rule, location)

            result_items.append(finding)

        return result_items

    def get_finding_cwes(self, result):
        """
        Hook method for subclasses to extract custom CWE values from result.
        Override this method to add custom CWE extraction logic.
        """
        return []

    def get_finding_title(self, result, rule, location):
        """
        Get title for the finding. Subclasses can override this method
        to add custom title formatting. Use super() to get the base title.
        """
        title = None
        if "message" in result:
            title = get_message_from_multiformatMessageString(
                result["message"], rule,
            )
        if title is None and rule is not None:
            if "shortDescription" in rule:
                title = get_message_from_multiformatMessageString(
                    rule["shortDescription"], rule,
                )
            elif "fullDescription" in rule:
                title = get_message_from_multiformatMessageString(
                    rule["fullDescription"], rule,
                )
            elif "name" in rule:
                title = rule["name"]
            elif "id" in rule:
                title = rule["id"]

        if title is None:
            msg = "No information found to create a title"
            raise ValueError(msg)

        return textwrap.shorten(title, 150)

    def get_finding_description(self, result, rule, location):
        """
        Get description for the finding. Subclasses can override this method
        to add custom description formatting. Use super() to get the base description.
        """
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
                if fullDescription not in {message, shortDescription}:
                    description += f"**{_('Rule full description')}:** {fullDescription}\n"

        if len(result.get("codeFlows", [])) > 0:
            description += get_codeFlowsDescription(result["codeFlows"])

        return description.removesuffix("\n")

    def get_finding_type(self):
        """
        Hook method for subclasses to specify finding type.
        Returns tuple of (static_finding, dynamic_finding).
        """
        return (True, False)  # SARIF is static by definition

    def customize_finding(self, finding, result, rule, location):
        """
        Hook method for subclasses to customize the finding after creation.
        Override this method to add custom fields or modify the finding.
        """


def get_rules(run):
    rules = {}
    rules_array = run["tool"]["driver"].get("rules", [])
    if len(rules_array) == 0 and run["tool"].get("extensions") is not None:
        rules_array = run["tool"]["extensions"][0].get("rules", [])
    for item in rules_array:
        rules[item["id"]] = item
    return rules


# Rules and results have de sames scheme for tags
def get_properties_tags(value):
    if not value:
        return []
    return value.get("properties", {}).get("tags", [])


def search_cwe(value, cwes):
    matches = re.search(CWE_REGEX, value, re.IGNORECASE)
    if matches:
        cwes.append(int(matches[0].split("-")[1]))


def get_rule_cwes(rule):
    cwes = []
    # data of the specification
    if "relationships" in rule and isinstance(rule["relationships"], list):
        for relationship in rule["relationships"]:
            value = relationship["target"]["id"]
            search_cwe(value, cwes)
        return cwes

    # Check for CWE values in rule properties (e.g., Snyk Code)
    if "properties" in rule and "cwe" in rule["properties"]:
        cwe_values = rule["properties"]["cwe"]
        if isinstance(cwe_values, list):
            for cwe_value in cwe_values:
                search_cwe(cwe_value, cwes)
        else:
            search_cwe(cwe_values, cwes)
        return cwes

    for tag in get_properties_tags(rule):
        search_cwe(tag, cwes)
    return cwes


def get_result_cwes_properties(result):
    """Some tools like njsscan store the CWE in the properties of the result"""
    cwes = []
    if "properties" in result and "cwe" in result["properties"]:
        value = result["properties"]["cwe"]
        search_cwe(value, cwes)
    return cwes


def get_result_cwes_taxa(result):
    """Extract CWEs from SARIF taxa (official SARIF approach)"""
    cwes = []
    if "taxa" in result and isinstance(result["taxa"], list):
        for taxon in result["taxa"]:
            if isinstance(taxon, dict):
                # Check if this is a CWE taxonomy reference
                tool_component = taxon.get("toolComponent", {})
                if tool_component.get("name") == "CWE":
                    cwe_id = taxon.get("id")
                    if cwe_id:
                        try:
                            cwes.append(int(cwe_id))
                        except ValueError:
                            # Handle cases where CWE ID is not a pure number
                            search_cwe(f"CWE-{cwe_id}", cwes)
    return cwes


def get_artifacts(run):
    artifacts = {}
    for custom_index, tree_artifact in enumerate(run.get("artifacts", [])):
        artifacts[tree_artifact.get("index", custom_index)] = tree_artifact
    return artifacts


def get_message_from_multiformatMessageString(data, rule):
    """
    Get a message from multimessage struct

    See here for the specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317468
    """
    if rule is not None and "id" in data:
        text = rule["messageStrings"][data["id"]].get("text")
        arguments = data.get("arguments", [])
        # argument substitution
        for i in range(6):  # the specification limit to 6
            substitution_str = "{" + str(i) + "}"
            if substitution_str in text:
                text = text.replace(substitution_str, arguments[i])
            else:
                return text
        return None
    # TODO: manage markdown
    return data.get("text")


def cve_try(val):
    # Match only the first CVE!
    cveSearch = re.search(r"(CVE-[0-9]+-[0-9]+)", val, re.IGNORECASE)
    if cveSearch:
        return cveSearch.group(1).upper()
    return None


def get_snippet(location):

    snippet = None

    if location and "physicalLocation" in location:
        if "region" in location["physicalLocation"]:
            if "snippet" in location["physicalLocation"]["region"]:
                if (
                    "text"
                    in location["physicalLocation"]["region"]["snippet"]
                ):
                    snippet = location["physicalLocation"]["region"][
                        "snippet"
                    ]["text"]
        if (
            snippet is None
            and "contextRegion" in location["physicalLocation"]
        ):
            if "snippet" in location["physicalLocation"]["contextRegion"]:
                if (
                    "text"
                    in location["physicalLocation"]["contextRegion"][
                        "snippet"
                    ]
                ):
                    snippet = location["physicalLocation"][
                        "contextRegion"
                    ]["snippet"]["text"]

    return snippet


def get_codeFlowsDescription(code_flows):
    description = ""
    for codeFlow in code_flows:
        for threadFlow in codeFlow.get("threadFlows", []):
            if "locations" not in threadFlow:
                continue

            description = f"**{_('Code flow')}:**\n"

            for line, location in enumerate(threadFlow.get("locations", [])):
                physicalLocation = location.get("location", {}).get("physicalLocation", {})
                region = physicalLocation.get("region", {})
                uri = physicalLocation.get("artifactLocation").get("uri")

                start_line = ""
                start_column = ""
                snippet = ""

                if "startLine" in region:
                    start_line = f":L{region.get('startLine')}"

                if "startColumn" in region:
                    start_column = f":C{region.get('startColumn')}"

                if "snippet" in region:
                    snippet = f"\t-\t{region.get('snippet').get('text')}"

                description += f"{line + 1}. {uri}{start_line}{start_column}{snippet}\n"

                if "message" in location.get("location", {}):
                    message_field = location.get("location", {}).get("message", {})
                    if "markdown" in message_field:
                        message = message_field.get("markdown", "")
                    else:
                        message = message_field.get("text", "")

                    description += f"\t{message}\n"

    return description


def get_references(rule):
    reference = None
    if rule is not None:
        if "helpUri" in rule:
            reference = rule["helpUri"]
        elif "help" in rule:
            helpText = get_message_from_multiformatMessageString(
                rule["help"], rule,
            )
            if helpText.startswith("http"):
                reference = helpText

    return reference


def cvss_to_severity(cvss):
    severity_mapping = {
        1: "Info",
        2: "Low",
        3: "Medium",
        4: "High",
        5: "Critical",
    }

    if cvss >= 9:
        return severity_mapping.get(5)
    if cvss >= 7:
        return severity_mapping.get(4)
    if cvss >= 4:
        return severity_mapping.get(3)
    if cvss > 0:
        return severity_mapping.get(2)
    return severity_mapping.get(1)


def get_severity(result, rule):
    severity = result.get("level")
    if severity is None and rule is not None:
        # get the severity from the rule
        if "defaultConfiguration" in rule:
            severity = rule["defaultConfiguration"].get("level")

    if severity == "note":
        return "Info"
    if severity == "warning":
        return "Medium"
    if severity == "error":
        return "High"
    return "Medium"


def get_fingerprints_hashes(values):
    """
    Method that generate a `unique_id_from_tool` data from the `fingerprints` attribute.
     - for now, we take the value of the last version of the first hash method.
    """
    fingerprints = {}
    for key in values:
        if "/" in key:
            key_method = key.split("/")[-2]
            key_method_version = int(key.split("/")[-1].replace("v", ""))
        else:
            key_method = key
            key_method_version = 0
        value = values[key]
        if fingerprints.get(key_method):
            if fingerprints[key_method]["version"] < key_method_version:
                fingerprints[key_method] = {
                    "version": key_method_version,
                    "value": value,
                }
        else:
            fingerprints[key_method] = {
                "version": key_method_version,
                "value": value,
            }
    return fingerprints
