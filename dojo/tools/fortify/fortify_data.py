from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import datetime


class VulnerabilityData:

    def _map_severity(self, severity):
        severity_mapping = {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "NEGLIGIBLE": "Informational",
        }

        return severity_mapping.get(severity, "Informational")

    """
    Data class to represent the Sysdig data extracted from sources like CSV or JSON.
    """
    def __init__(self):
        self.vulnerability_type: str = ""
        self.class_id: str = ""
        self.kingdom: str = ""
        self.analyzer_name: str = ""
        self.default_severity: str = ""

        self.instance_id: str = ""
        self.instance_severity: str = ""
        self.confidence: str = ""

        self.source_location_path: str = ""
        self.source_location_line: str = ""
        self.source_location_line_end: str = ""
        self.source_location_col_start: str = ""
        self.source_location_col_end: str = ""
        self.snippet_id: str = ""


class SnippetData:
    def __init__(self):
        self.file_name: str = ""
        self.start_line: str = ""
        self.end_line: str = ""
        self.text: str = ""


class DescriptionData:
    def __init__(self):
        self.abstract: str = ""
        self.explanation: str = ""
        self.recommendations: str = ""
        self.tips: str = ""
        self.references: str = ""  # TODO: parse this?


class RuleData:
    def __init__(self):
        self.accuracy: str = ""
        self.impact: str = ""
        self.probability: str = ""
        self.impact_bias: str = ""
        self.confidentiality_impact: str = ""
        self.integrity_impact: str = ""
        self.remediation_effort: str = ""
