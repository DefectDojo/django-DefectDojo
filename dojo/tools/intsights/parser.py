import collections
import csv
import io
import json
import logging

from dojo.models import Finding


class IntSightsParser(object):
    """
    IntSights Threat Intelligence Report
    """

    _LOGGER = logging.getLogger(__name__)

    def get_scan_types(self):
        return ["IntSights Report"]

    def get_label_for_scan_types(self, scan_type):
        return "IntSights Report"

    def get_description_for_scan_types(self, scan_type):
        return "IntSights report file can be imported in JSON format."

    def _parse_json(self, json_file) -> [dict]:
        """
        Parses entries from the JSON object into a list of alerts
        Args:
            json_file: The JSON file object to parse
        Returns:
            A list of alerts [dict()]
        """
        alerts = []

        original_alerts = json.load(json_file)
        for original_alert in original_alerts.get('Alerts', []):
            alert = dict()
            alert['alert_id'] = original_alert['_id']
            alert['title'] = original_alert['Details']['Title']
            alert['description'] = original_alert['Details']['Description']
            alert['severity'] = original_alert['Details']['Severity']
            alert['type'] = original_alert['Details']['Type']
            alert['source_date'] = original_alert['Details']['Source'].get("Date", "None provided")
            alert['report_date'] = original_alert.get("FoundDate", "None provided")
            alert['network_type'] = original_alert['Details']['Source'].get('NetworkType')
            alert['source_url'] = original_alert['Details']['Source'].get('URL')
            alert['assets'] = ','.join([item.get('Value') for item in original_alert['Assets']])
            alert['tags'] = original_alert['Details'].get('Tags')
            alert['status'] = 'Closed' if original_alert['Closed'].get('IsClosed') else 'Open'
            alert[
                'alert_link'] = f'https://dashboard.intsights.com/#/threat-command/alerts?search=' \
                                f'{original_alert["_id"]}'

            alerts.append(alert)

        return alerts

    def _parse_csv(self, csv_file) -> [dict]:
        """

        Parses entries from the CSV file object into a list of alerts
        Args:
            csv_file: The JSON file object to parse
        Returns:
            A list of alerts [dict()]

        """
        default_keys = ['Alert ID', 'Title', 'Description', 'Severity', 'Type', 'Source Date (UTC)',
                        'Report Date (UTC)', 'Network Type', 'Source URL', 'Source Name', 'Assets', 'Tags',
                        'Assignees', 'Remediation', 'Status', 'Closed Reason', 'Additional Info', 'Rating',
                        'Alert Link']

        # These keys require a value. If one ore more of the values is null or empty, the entire Alert is ignored.
        # This is to avoid attempting to import incomplete Findings.
        required_keys = ['alert_id', 'title', 'severity', 'status']

        alerts = []
        invalid_alerts = []

        content = csv_file.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        csv_reader = csv.DictReader(io.StringIO(content), delimiter=',', quotechar='"')

        # Don't bother parsing if the keys don't match exactly what's expected
        if collections.Counter(default_keys) == collections.Counter(csv_reader.fieldnames):
            default_valud = 'None provided'
            for alert in csv_reader:
                alert['alert_id'] = alert.pop('Alert ID')
                alert['title'] = alert.pop('Title')
                alert['description'] = alert.pop('Description')
                alert['severity'] = alert.pop('Severity')
                alert['type'] = alert.pop('Type', )
                alert['source_date'] = alert.pop('Source Date (UTC)', default_valud)
                alert['report_date'] = alert.pop('Report Date (UTC)', default_valud)
                alert['network_type'] = alert.pop('Network Type', default_valud)
                alert['source_url'] = alert.pop('Source URL', default_valud)
                alert['assets'] = alert.pop('Assets', default_valud)
                alert['tags'] = alert.pop('Tags', default_valud)
                alert['status'] = alert.pop('Status', default_valud)
                alert['alert_link'] = alert.pop('Alert Link')
                alert.pop('Assignees')
                alert.pop('Remediation')
                alert.pop('Closed Reason')
                alert.pop('Rating')
                for key in required_keys:
                    if not alert[key]:
                        invalid_alerts.append(alert)

                if alert not in invalid_alerts:
                    alerts.append(alert)
        else:
            self._LOGGER.error('The CSV file has one or more missing or unexpected header values')

        return alerts

    def _build_finding_description(self, alert: dict) -> str:
        """
        Builds an IntSights Finding description from various pieces of information.
        Args:
            alert: The parsed alert dictionary
        Returns: A markdown formatted description
        """

        description = "\n".join([
            alert["description"],
            f'**Date Found**: `{alert.get("report_date", "None provided")} `',
            f'**Type**: `{alert.get("type", "None provided")} `',
            f'**Source**: `{alert.get("source_url", "None provided")} `',
            f'**Source Date**: ` {alert.get("source_date", "None provided")} `',
            f'**Source Network Type**: `{alert.get("network_type", "None provided")} `',
            f'**Assets Affected**: `{alert.get("assets", "None provided")} `',
            f'**Alert Link**: {alert.get("alert_link", "None provided")}'
        ])
        return description

    def get_findings(self, file, test):
        duplicates = dict()

        if file.name.lower().endswith('.json'):
            alerts = self._parse_json(file, )
        elif file.name.lower().endswith('.csv'):
            alerts = self._parse_csv(file)
        else:
            raise ValueError('Filename extension not recognized. Use .json or .csv')

        if not alerts:
            raise ValueError('No alert in the report')

        for alert in alerts:
            dupe_key = alert['alert_id']

            alert = Finding(title=alert['title'],
                            test=test,
                            active=False if alert['status'] == 'Closed' else True,
                            verified=True,
                            description=self._build_finding_description(alert),
                            severity=alert['severity'],
                            references=alert["alert_link"],
                            static_finding=False,
                            dynamic_finding=True,
                            unique_id_from_tool=alert['alert_id'])

            duplicates[dupe_key] = alert

            if dupe_key not in duplicates:
                duplicates[dupe_key] = True

        return duplicates.values()
