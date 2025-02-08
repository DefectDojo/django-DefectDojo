import re
import zipfile
from xml.etree.ElementTree import Element

from defusedxml import ElementTree

from dojo.models import Finding, Test


class FortifyFPRParser:
    def parse_fpr(self, filename, test):
        if str(filename.__class__) == "<class '_io.TextIOWrapper'>":
            input_zip = zipfile.ZipFile(filename.name, "r")
        else:
            input_zip = zipfile.ZipFile(filename, "r")
        # Read each file from the zip artifact into a dict with the format of
        # filename: file_content
        zip_data = {name: input_zip.read(name) for name in input_zip.namelist()}
        root = self.identify_root(zip_data)
        return self.parse_vulnerabilities_and_convert_to_findings(root, test)

    def identify_root(self, zip_data: dict) -> Element:
        """Iterate through the zip data to determine which file in the zip could be the XMl to be parsed."""
        # Determine where the "audit.fvdl" could be
        audit_file = None
        for file_name in zip_data:
            if file_name.endswith("audit.fvdl"):
                audit_file = file_name
                break
        # Make sure we have an audit file
        if audit_file is None:
            msg = 'A search for an "audit.fvdl" file was not successful. '
            raise ValueError(msg)
        # Parser the XML file and determine the name space, if present
        root = ElementTree.fromstring(zip_data.get(audit_file).decode("utf-8"))
        self.identify_namespace(root)
        return root

    def identify_namespace(self, root: Element) -> None:
        """Determine what the namespace could be, and then set the value in a class var labeled `namespace`"""
        regex = r"{.*}"
        matches = re.match(regex, root.tag)
        try:
            self.namespace = matches.group(0)
        except BaseException:
            self.namespace = ""

    def parse_vulnerabilities_and_convert_to_findings(self, root: Element, test: Test) -> list[Finding]:
        """Parse the XML and generate a list of findings."""
        items = []
        for child in root:
            if "Vulnerabilities" in child.tag:
                for vuln in child:
                    finding_context = {
                        "title": "",
                        "description": "",
                        "static_finding": True,
                        "test": test,
                    }
                    self.parse_class_information(vuln, finding_context)
                    self.parse_instance_information(vuln, finding_context)
                    self.parse_analysis_information(vuln, finding_context)
                    self.parse_severity_and_convert(vuln, finding_context)
                    items.append(Finding(**finding_context))
        return items

    def parse_severity_and_convert(self, vulnerability: Element, finding_context: dict) -> None:
        """Convert the the float representation of severity and confidence to a string severity."""
        # Default info severity in the case of an error
        severity = "Info"
        instance_severity = None
        confidence = None
        # Attempt to fetch the confidence and instance severity
        if (instance_info := vulnerability.find(f"{self.namespace}InstanceInfo")) is not None:
            instance_severity = getattr(instance_info.find(f"{self.namespace}InstanceSeverity"), "text", None)
            confidence = getattr(instance_info.find(f"{self.namespace}Confidence"), "text", None)
        # Make sure we have something to work with
        if confidence is not None and instance_severity is not None:
            if float(confidence) >= 2.5 and float(instance_severity) >= 2.5:
                severity = "Critical"
            elif float(confidence) >= 2.5 and float(instance_severity) < 2.5:
                severity = "High"
            elif float(confidence) < 2.5 and float(instance_severity) >= 2.5:
                severity = "Medium"
            elif float(confidence) < 2.5 and float(instance_severity) < 2.5:
                severity = "Low"
        # Return either info, or the calculated severity
        finding_context["severity"] = severity

    def parse_class_information(self, vulnerability: Element, finding_context: dict) -> None:
        """Appends the description with any class information that can be extracted."""
        if (class_info := vulnerability.find(f"{self.namespace}ClassInfo")) is not None:
            if (namespace_type := class_info.find(f"{self.namespace}Type")) is not None:
                finding_context["description"] += f"{namespace_type.text}\n"
                finding_context["title"] += f"{namespace_type.text}"
            if (class_id := class_info.find(f"{self.namespace}ClassID")) is not None:
                finding_context["description"] += f"**ClassID:** {class_id.text}\n"
                finding_context["unique_id_from_tool"] = class_id.text
                finding_context["title"] += f" {class_id.text}"
            if (kingdom := class_info.find(f"{self.namespace}Kingdom")) is not None:
                finding_context["description"] += f"**Kingdom:** {kingdom.text}\n"
            if (analyzer_name := class_info.find(f"{self.namespace}AnalyzerName")) is not None:
                finding_context["description"] += f"**AnalyzerName:** {analyzer_name.text}\n"
            if (default_severity := class_info.find(f"{self.namespace}DefaultSeverity")) is not None:
                finding_context["description"] += f"**DefaultSeverity:** {default_severity.text}\n"

    def parse_instance_information(self, vulnerability: Element, finding_context: dict) -> None:
        """Appends the description with any instance information that can be extracted."""
        if (instance_info := vulnerability.find(f"{self.namespace}InstanceInfo")) is not None:
            if (instance_id := instance_info.find(f"{self.namespace}InstanceID")) is not None:
                finding_context["description"] += f"**InstanceID:** {instance_id.text}\n"
            if (instance_severity := instance_info.find(f"{self.namespace}InstanceSeverity")) is not None:
                finding_context["description"] += f"**InstanceSeverity:** {instance_severity.text}\n"
            if (confidence := instance_info.find(f"{self.namespace}Confidence")) is not None:
                finding_context["description"] += f"**Confidence:** {confidence.text}\n"

    def parse_analysis_information(self, vulnerability: Element, finding_context: dict) -> None:
        """Appends the description with any analysis information that can be extracted."""
        if (analysis_info := vulnerability.find(f"{self.namespace}AnalysisInfo")) is not None:
            # See if we can get a SourceLocation from this
            if (source_location := self.get_source_location(analysis_info)) is not None:
                path = source_location.attrib.get("path")
                line = source_location.attrib.get("line")
                # Managed the description
                finding_context["description"] += f"**SourceLocationPath:** {path}\n"
                finding_context["description"] += f"**SourceLocationLine:** {line}\n"
                finding_context["description"] += (
                    f"**SourceLocationLineEnd:** {source_location.attrib.get('lineEnd')}\n"
                )
                finding_context["description"] += (
                    f"**SourceLocationColStart:** {source_location.attrib.get('colStart')}\n"
                )
                finding_context["description"] += f"**SourceLocationColEnd:** {source_location.attrib.get('colEnd')}\n"
                finding_context["description"] += (
                    f"**SourceLocationSnippet:** {source_location.attrib.get('snippet')}\n"
                )
                # manage the other metadata
                finding_context["file_path"] = path
                finding_context["line"] = line

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
            if (next_current_element := current_element.find(f"{self.namespace}{key}")) is not None:
                current_element = next_current_element
            else:
                return None
        # Iterate over all "Entry" elements
        entries = current_element.findall(f"{self.namespace}Entry")
        for entry in entries:
            # Continue the search for "Node" and "SourceLocation" within each entry
            if (node := entry.find(f"{self.namespace}Node")) is not None:
                if (source_location := node.find(f"{self.namespace}SourceLocation")) is not None:
                    return source_location
        # Return None if no SourceLocation was found in any Entry
        return None
