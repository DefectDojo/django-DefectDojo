import re
import zipfile
from defusedxml import ElementTree
from dojo.models import Finding


class FortifyFPRParser(object):
    def parse_fpr(self, filename, test):
        if str(filename.__class__) == "<class '_io.TextIOWrapper'>":
            input_zip = zipfile.ZipFile(filename.name, 'r')
        else:
            input_zip = zipfile.ZipFile(filename, 'r')
        zipdata = {name: input_zip.read(name) for name in input_zip.namelist()}
        root = ElementTree.fromstring(zipdata["audit.fvdl"].decode('utf-8'))
        regex = r"{.*}"
        matches = re.match(regex, root.tag)
        try:
            namespace = matches.group(0)
        except BaseException:
            namespace = ""
        items = list()
        for child in root:
            if "Vulnerabilities" in child.tag:
                for vuln in child:
                    ClassID = vuln.find(f"{namespace}ClassInfo").find(f"{namespace}ClassID").text
                    Kingdom = vuln.find(f"{namespace}ClassInfo").find(f"{namespace}Kingdom").text
                    Type = vuln.find(f"{namespace}ClassInfo").find(f"{namespace}Type").text
                    AnalyzerName = vuln.find(f"{namespace}ClassInfo").find(f"{namespace}AnalyzerName").text
                    DefaultSeverity = vuln.find(f"{namespace}ClassInfo").find(f"{namespace}DefaultSeverity").text
                    InstanceID = vuln.find(f"{namespace}InstanceInfo").find(f"{namespace}InstanceID").text
                    InstanceSeverity = vuln.find(f"{namespace}InstanceInfo").find(f"{namespace}InstanceSeverity").text
                    Confidence = vuln.find(f"{namespace}InstanceInfo").find(f"{namespace}Confidence").text
                    SourceLocationpath = vuln.find(f"{namespace}AnalysisInfo").find(f"{namespace}Unified").find(f"{namespace}Trace").find(f"{namespace}Primary").find(f"{namespace}Entry").find(f"{namespace}Node").find(f"{namespace}SourceLocation").attrib.get("path")
                    SourceLocationline = vuln.find(f"{namespace}AnalysisInfo").find(f"{namespace}Unified").find(f"{namespace}Trace").find(f"{namespace}Primary").find(f"{namespace}Entry").find(f"{namespace}Node").find(f"{namespace}SourceLocation").attrib.get("line")
                    SourceLocationlineEnd = vuln.find(f"{namespace}AnalysisInfo").find(f"{namespace}Unified").find(f"{namespace}Trace").find(f"{namespace}Primary").find(f"{namespace}Entry").find(f"{namespace}Node").find(f"{namespace}SourceLocation").attrib.get("lineEnd")
                    SourceLocationcolStart = vuln.find(f"{namespace}AnalysisInfo").find(f"{namespace}Unified").find(f"{namespace}Trace").find(f"{namespace}Primary").find(f"{namespace}Entry").find(f"{namespace}Node").find(f"{namespace}SourceLocation").attrib.get("colStart")
                    SourceLocationcolEnd = vuln.find(f"{namespace}AnalysisInfo").find(f"{namespace}Unified").find(f"{namespace}Trace").find(f"{namespace}Primary").find(f"{namespace}Entry").find(f"{namespace}Node").find(f"{namespace}SourceLocation").attrib.get("colEnd")
                    SourceLocationsnippet = vuln.find(f"{namespace}AnalysisInfo").find(f"{namespace}Unified").find(f"{namespace}Trace").find(f"{namespace}Primary").find(f"{namespace}Entry").find(f"{namespace}Node").find(f"{namespace}SourceLocation").attrib.get("snippet")
                    description = Type + "\n"
                    severity = self.fpr_severity(Confidence, InstanceSeverity)
                    description += "**ClassID:** " + ClassID + "\n"
                    description += "**Kingdom:** " + Kingdom + "\n"
                    description += "**AnalyzerName:** " + AnalyzerName + "\n"
                    description += "**DefaultSeverity:** " + DefaultSeverity + "\n"
                    description += "**InstanceID:** " + InstanceID + "\n"
                    description += "**InstanceSeverity:** " + InstanceSeverity + "\n"
                    description += "**Confidence:** " + Confidence + "\n"
                    description += "**SourceLocationpath:** " + str(SourceLocationpath) + "\n"
                    description += "**SourceLocationline:** " + str(SourceLocationline) + "\n"
                    description += "**SourceLocationlineEnd:** " + str(SourceLocationlineEnd) + "\n"
                    description += "**SourceLocationcolStart:** " + str(SourceLocationcolStart) + "\n"
                    description += "**SourceLocationcolEnd:** " + str(SourceLocationcolEnd) + "\n"
                    description += "**SourceLocationsnippet:** " + str(SourceLocationsnippet) + "\n"
                    items.append(
                        Finding(
                              title=Type + " " + ClassID,
                              severity=severity,
                              static_finding=True,
                              test=test,
                              description=description,
                              unique_id_from_tool=ClassID,
                              file_path=SourceLocationpath,
                              line=SourceLocationline,
                        )
                    )
        return items

    def fpr_severity(self, Confidence, InstanceSeverity):
        if float(Confidence) >= 2.5 and float(InstanceSeverity) >= 2.5:
            severity = "Critical"
        elif float(Confidence) >= 2.5 and float(InstanceSeverity) < 2.5:
            severity = "High"
        elif float(Confidence) < 2.5 and float(InstanceSeverity) >= 2.5:
            severity = "Medium"
        elif float(Confidence) < 2.5 and float(InstanceSeverity) < 2.5:
            severity = "Low"
        else:
            severity = "Info"
        return severity
