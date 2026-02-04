import logging

from dojo.models import Finding
from dojo.tools.intsights.csv_handler import IntSightsCSVParser
from dojo.tools.intsights.json_handler import IntSightsJSONParser


class IntSightsParser:

    """IntSights Threat Intelligence Report"""

    _LOGGER = logging.getLogger(__name__)

    def get_scan_types(self):
        return ["IntSights Report"]

    def get_label_for_scan_types(self, scan_type):
        return "IntSights Report"

    def get_description_for_scan_types(self, scan_type):
        return "IntSights report file can be imported in JSON format."

    def _build_finding_description(self, alert: dict) -> str:
        """
        Builds an IntSights Finding description from various pieces of information.

        Args:
            alert: The parsed alert dictionary
        Returns: A markdown formatted description

        """
        return "\n".join(
            [
                alert["description"],
                f'**Date Found**: `{alert.get("report_date", "None provided")} `',
                f'**Type**: `{alert.get("type", "None provided")} `',
                f'**Source**: `{alert.get("source_url", "None provided")} `',
                f'**Source Date**: ` {alert.get("source_date", "None provided")} `',
                f'**Source Network Type**: `{alert.get("network_type", "None provided")} `',
                f'**Assets Affected**: `{alert.get("assets", "None provided")} `',
                f'**Alert Link**: {alert.get("alert_link", "None provided")}',
            ],
        )

    def get_findings(self, file, test):
        duplicates = {}
        if file.name.lower().endswith(".json"):
            alerts = IntSightsJSONParser()._parse_json(
                file,
            )
        elif file.name.lower().endswith(".csv"):
            alerts = IntSightsCSVParser()._parse_csv(file)
        else:
            msg = "Filename extension not recognized. Use .json or .csv"
            raise ValueError(msg)
        for alert in alerts:
            dupe_key = alert["alert_id"]
            uniq_alert = Finding(
                title=alert["title"],
                test=test,
                active=alert["status"] != "Closed",
                verified=True,
                description=self._build_finding_description(alert),
                severity=alert["severity"],
                references=alert["alert_link"],
                static_finding=False,
                dynamic_finding=True,
                unique_id_from_tool=alert["alert_id"],
            )
            duplicates[dupe_key] = uniq_alert
            if dupe_key not in duplicates:
                duplicates[dupe_key] = True
        return list(duplicates.values())
