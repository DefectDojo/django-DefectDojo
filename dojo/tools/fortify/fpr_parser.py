import logging
import re
import zipfile
from xml.etree.ElementTree import Element

from defusedxml import ElementTree

from dojo.models import Finding, Test
from dojo.tools.fortify.fortify_data import DescriptionData, RuleData, SnippetData, VulnerabilityData

logger = logging.getLogger(__name__)


class FortifyRelatedData:
    def __init__(self):
        self.descriptions: dict[str, DescriptionData] = {}
        self.snippets: dict[str, SnippetData] = {}
        self.rules: dict[str, RuleData] = {}
        self.vulnerabilities: list[VulnerabilityData] = []
        self.suppressed: dict[str, bool] = {}
        self.threaded_comments: dict[str, list[str]] = {}


class FortifyFPRParser:
    def __init__(self):
        pass

    def parse_fpr(self, filename, test):
        if str(filename.__class__) == "<class '_io.TextIOWrapper'>":
            input_zip = zipfile.ZipFile(filename.name, "r")
        else:
            input_zip = zipfile.ZipFile(filename, "r")
        # Read each file from the zip artifact into a dict with the format of
        # filename: file_content
        zip_data = {name: input_zip.read(name) for name in input_zip.namelist()}
        root, self.namespaces = self.identify_root(zip_data, "audit.fvdl", "No audit.fvdl file found in the zip")
        audit_log, self.namespaces_audit_log = self.identify_root(zip_data, "audit.xml")
        return self.convert_vulnerabilities_to_findings(root, audit_log, test)

    def identify_root(self, zip_data: dict, filename_suffix: str, msg_if_not_found: str | None = None) -> tuple[Element, dict[str, str]]:
        """Iterate through the zip data to determine which file in the zip could be the XML to be parsed."""
        # Determine where the "audit.fvdl" could be
        audit_file = None
        for file_name in zip_data:
            if file_name.endswith(filename_suffix):
                audit_file = file_name
                break
        # Make sure we have an audit file
        if audit_file is None and msg_if_not_found:
            raise ValueError(msg_if_not_found)

        if not audit_file:
            return None, None

        # Parse the XML file and determine the namespace, if present
        root = ElementTree.fromstring(zip_data.get(audit_file).decode("utf-8"))
        namespaces = self.identify_namespace(root)
        return root, namespaces

    def identify_namespace(self, root: Element) -> dict[str, str]:
        """Determine what the namespace could be, and then set the value in a class var labeled `namespaces`"""
        regex = r"{(.*)}"
        matches = re.match(regex, root.tag)
        return {"": matches.group(1)}

    def parse_related_data(self, root: Element, test: Test) -> None:
        """Parse the XML and generate a list of findings."""
        related_data = FortifyRelatedData()
        for description in root.findall("Description", self.namespaces):
            class_id = description.attrib.get("classID")
            logger.debug(f"Description: {class_id}")
            if class_id:
                related_data.descriptions[class_id] = self.parse_description_information(description)

        for snippet in root.find("Snippets", self.namespaces):
            snippet_id = snippet.attrib.get("id")
            logger.debug(f"Snippet: {snippet_id}")
            if snippet_id:
                related_data.snippets[snippet_id] = self.parse_snippet_information(snippet)

        for rule in root.find("EngineData", self.namespaces).find("RuleInfo", self.namespaces):
            rule_id = rule.attrib.get("id")
            logger.debug(f"Rule: {rule_id}")
            if rule_id:
                related_data.rules[rule_id] = self.parse_rule_information(rule.find("MetaInfo", self.namespaces))
        return related_data

    def add_audit_log(self, related_data, audit_log: Element) -> None:
        logger.debug("Parse audit log")
        if audit_log is None:
            return related_data

        for issue in audit_log.find("IssueList", self.namespaces_audit_log).findall("Issue", self.namespaces_audit_log):
            instance_id = issue.attrib.get("instanceId")
            if instance_id:
                suppressed_string = issue.attrib.get("suppressed")
                suppressed = suppressed_string.lower() == "true" if suppressed_string else False
                logger.debug(f"Issue: {instance_id} - Suppressed: {suppressed}")
                related_data.suppressed[instance_id] = suppressed

                threaded_comments = issue.find("ThreadedComments", self.namespaces_audit_log)
                logger.debug(f"ThreadedComments: {threaded_comments}")
                if threaded_comments is not None:
                    related_data.threaded_comments[instance_id] = [self.get_comment_text(comment) for comment in threaded_comments.findall("Comment", self.namespaces_audit_log)]
        return related_data

    def get_comment_text(self, comment: Element) -> str:
        content = comment.findtext("Content", "", self.namespaces_audit_log)
        username = comment.findtext("Username", "", self.namespaces_audit_log)
        timestamp = comment.findtext("Timestamp", "", self.namespaces_audit_log)

        return f"{timestamp} - ({username}): {content}"

    def convert_vulnerabilities_to_findings(self, root: Element, audit_log: Element, test: Test) -> list[Finding]:
        """Convert the list of vulnerabilities to a list of findings."""
        """Try to mimic the logic from the xml parser"""
        """Future Improvement: share code between xml and fpr parser (it was split up earlier)"""
        related_data = self.parse_related_data(root, test)
        # add audit log information to related data
        related_data = self.add_audit_log(related_data, audit_log)

        findings = []
        for vuln in root.find("Vulnerabilities", self.namespaces):
            vuln_data = VulnerabilityData()
            self.parse_instance_information(vuln, vuln_data)
            self.parse_class_information(vuln, vuln_data)
            self.parse_analysis_information(vuln, vuln_data)

            snippet = related_data.snippets.get(vuln_data.snippet_id)
            description = related_data.descriptions.get(vuln_data.class_id)
            rule = related_data.rules.get(vuln_data.class_id)

            finding = Finding(test=test, static_finding=True)

            finding.active, finding.false_p = self.compute_status(related_data, vuln_data)
            finding.title = self.format_title(vuln_data, snippet, description, rule)
            finding.description = self.format_description(vuln_data, snippet, description, rule)
            finding.mitigation = self.format_mitigation(vuln_data, snippet, description, rule)
            finding.severity = self.compute_severity(vuln_data, snippet, description, rule)
            finding.impact = self.format_impact(related_data, vuln_data)

            finding.file_path = vuln_data.source_location_path
            finding.line = int(self.compute_line(vuln_data, snippet, description, rule))
            finding.unique_id_from_tool = vuln_data.instance_id

            findings.append(finding)

        return findings

    def parse_class_information(self, vulnerability: Element, vuln_data: VulnerabilityData) -> None:
        if (class_info := vulnerability.find("ClassInfo", self.namespaces)) is not None:
            vuln_data.vulnerability_type = class_info.findtext("Type", None, self.namespaces)
            vuln_data.class_id = class_info.findtext("ClassID", None, self.namespaces)
            vuln_data.kingdom = class_info.findtext("Kingdom", None, self.namespaces)
            vuln_data.analyzer_name = class_info.findtext("AnalyzerName", None, self.namespaces)
            vuln_data.default_severity = class_info.findtext("DefaultSeverity", None, self.namespaces)

    def parse_instance_information(self, vulnerability: Element, vuln_data: VulnerabilityData) -> None:
        # Attempt to fetch the confidence and instance severity
        if (instance_info := vulnerability.find("InstanceInfo", self.namespaces)) is not None:
            vuln_data.instance_id = instance_info.findtext("InstanceID", None, self.namespaces)
            vuln_data.instance_severity = instance_info.findtext("InstanceSeverity", None, self.namespaces)
            vuln_data.confidence = instance_info.findtext("Confidence", None, self.namespaces)

    def parse_analysis_information(self, vulnerability: Element, vuln_data: VulnerabilityData) -> None:
        """Appends the description with any analysis information that can be extracted."""
        if (analysis_info := vulnerability.find("AnalysisInfo", self.namespaces)) is not None:
            # See if we can get a SourceLocation from this
            if (source_location := self.get_source_location(analysis_info)) is not None:
                vuln_data.source_location_path = source_location.attrib.get("path")
                vuln_data.source_location_line = source_location.attrib.get("line")
                vuln_data.source_location_line_end = source_location.attrib.get("lineEnd")
                vuln_data.source_location_col_start = source_location.attrib.get("colStart")
                vuln_data.source_location_col_end = source_location.attrib.get("colEnd")
                vuln_data.snippet_id = source_location.attrib.get("snippet")

    def get_source_location(self, analysis_info: Element) -> Element | None:
        """Return the SourceLocation element if we are able to reach it."""
        # The order of this list is very important. Do not reorder it!
        key_path = [
            "Unified",
            "Trace",
            "Primary",
            "Entry",
            "Node",
            "SourceLocation",
        ]
        # iterate of the keys until we find something that cannot be fulfilled
        current_element = analysis_info
        # Traverse the key path up to "Entry" to fetch all Entry elements
        for key in key_path[:-3]:  # stop before "Entry" level
            if (next_current_element := current_element.find(f"{key}", self.namespaces)) is not None:
                current_element = next_current_element
            else:
                return None
        # Iterate over all "Entry" elements
        entries = current_element.findall("Entry", self.namespaces)
        for entry in entries:
            # Continue the search for "Node" and "SourceLocation" within each entry
            if (node := entry.find("Node", self.namespaces)) is not None:
                if (source_location := node.find("SourceLocation", self.namespaces)) is not None:
                    return source_location
        # Return None if no SourceLocation was found in any Entry
        return None

    def parse_snippet_information(self, snippet: Element) -> SnippetData:
        """Parse the snippet information and return a SnippetData object."""
        snippet_data = SnippetData()
        snippet_data.file_name = snippet.findtext("File", None, self.namespaces)
        snippet_data.start_line = snippet.findtext("StartLine", None, self.namespaces)
        snippet_data.end_line = snippet.findtext("EndLine", None, self.namespaces)
        snippet_data.text = snippet.findtext("Text", None, self.namespaces)
        logger.debug(f"Snippet: {snippet_data.file_name}: {snippet_data.start_line}")
        return snippet_data

    def parse_description_information(self, description: Element) -> DescriptionData:
        """Parse the description information and return a DescriptionData object."""
        description_data = DescriptionData()
        description_data.abstract = description.findtext("Abstract", None, self.namespaces)
        description_data.explanation = description.findtext("Explanation", None, self.namespaces)
        description_data.recommendations = description.findtext("Recommendations", None, self.namespaces)
        description_data.tips = description.findtext("Tips", None, self.namespaces)
        return description_data

    def parse_rule_information(self, rule: Element) -> RuleData:
        """Parse the rule information and return a RuleData object."""
        rule_data = RuleData()
        rule_data.accuracy = rule.findtext("Group[@name='Accuracy']", None, self.namespaces)
        rule_data.impact = rule.findtext("Group[@name='Impact']", None, self.namespaces)
        rule_data.probability = rule.findtext("Group[@name='Probability']", None, self.namespaces)
        rule_data.impact_bias = rule.findtext("Group[@name='ImpactBias']", None, self.namespaces)
        rule_data.confidentiality_impact = rule.findtext("Group[@name='ConfidentialityImpact']", None, self.namespaces)
        rule_data.integrity_impact = rule.findtext("Group[@name='IntegrityImpact']", None, self.namespaces)
        rule_data.remediation_effort = rule.findtext("Group[@name='Recommendations']", None, self.namespaces)
        logger.debug(f"Rule Impact: {rule_data.impact}")
        return rule_data

    def format_title(self, vulnerability, snippet, description, rule) -> str:
        # defaults for when there is no snippet (shouldn't happen, future improvement: parser might also parse ReplacementDefinitions and/or Context elements)
        file_name = vulnerability.source_location_path.split("/")[-1]
        line = self.compute_line(vulnerability, snippet, description, rule)

        return f"{vulnerability.vulnerability_type} - {file_name}: {line} ({vulnerability.class_id})"

    def format_description(self, vulnerability, snippet, description, rule) -> str:
        desc = f"##Catagory: {vulnerability.vulnerability_type}\n"
        desc += f"###Abstract:\n{description.abstract}\n"

        desc += f"**SourceLocationPath:** {vulnerability.source_location_path}\n"
        desc += f"**SourceLocationLine:** {vulnerability.source_location_line}\n"
        desc += f"**SourceLocationLineEnd:** {vulnerability.source_location_line_end}\n"
        desc += f"**SourceLocationColStart:** {vulnerability.source_location_col_start}\n"
        desc += f"**SourceLocationColEnd:** {vulnerability.source_location_col_end}\n"

        if snippet:
            desc += (
                "##Source:\nThis snippet provides more context on the execution path that "
                "leads to this finding. \n")
            desc += f"###Snippet:\n**File: {snippet.file_name}: {snippet.start_line}**\n```\n{snippet.text}\n```\n"

        desc += f"##Explanation:\n {description.explanation}"

        desc += f"##Details: {vulnerability.instance_id}\n"
        desc += f"**InstanceID:** {vulnerability.instance_id}\n"
        desc += f"**InstanceSeverity:** {vulnerability.instance_severity}\n"
        desc += f"**Confidence:** {vulnerability.confidence}\n"
        desc += f"**ClassID:** {vulnerability.class_id}\n"
        desc += f"**Kingdom:** {vulnerability.kingdom}\n"
        desc += f"**AnalyzerName:** {vulnerability.analyzer_name}\n"
        desc += f"**DefaultSeverity:** {vulnerability.default_severity}\n"

        return desc

    def format_mitigation(self, vulnerability, snippet, description, rule) -> str:
        mitigation = ""
        if description.recommendations:
            mitigation += f"###Recommendation:\n {description.recommendations}\n"

        if description.tips:
            mitigation += f"###Tips:\n {description.tips}"
        return mitigation

    def compute_severity(self, vulnerability, snippet, description, rule) -> str:
        """Convert the the float representation of severity and confidence to a string severity."""
        if not rule.impact:
            logger.debug("No rule impact found, setting severity to Informational")
            return "Informational"

        try:
            impact = float(rule.impact)
            confidence = float(vulnerability.confidence)
            accuracy = float(rule.accuracy)
            probability = float(rule.probability)

            # This comes from Fortify support documentation, requested in #11901
            likelihood = (accuracy * confidence * probability) / 25
            likelihood = round(likelihood, 1)
            logger.debug(f"Impact: {impact}, Likelihood: {likelihood}")

            if impact >= 2.5 and likelihood >= 2.5:
                return "Critical"
            if impact >= 2.5 > likelihood:
                return "High"
            if impact < 2.5 <= likelihood:
                return "Medium"
            if impact < 2.5 and likelihood < 2.5:
                return "Low"

        except ValueError:
            logger.info("Impossible to compute severity due to number format error", exc_info=True)

        return "Informational"

    def format_impact(self, related_data, vuln_data) -> str:
        """Format the impact of the vulnerability based on the threaded comments."""
        logger.debug(f"Threaded comments: {related_data.threaded_comments}")
        threaded_comments = related_data.threaded_comments.get(vuln_data.instance_id)
        if not threaded_comments:
            return ""

        impact = "Threaded Comments:\n"
        for comment in related_data.threaded_comments[vuln_data.instance_id]:
            impact += f"{comment}\n"

        return impact

    def compute_status(self, related_data, vulnerability) -> tuple[bool, bool]:
        """Compute the status of the vulnerability based on the instance ID. Return active, false_p"""
        if vulnerability.instance_id in related_data.suppressed:
            return False, True
        return True, False

    def compute_line(self, vulnerability, snippet, description, rule) -> str:
        if snippet and snippet.start_line:
            return snippet.start_line
        return vulnerability.source_location_line
