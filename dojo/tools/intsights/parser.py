import collections
import csv
import io
import json
import logging

from dojo.models import Finding


class IntSightsParser(object):
    """
    IntSights Threat Intelligence Feed
    """

    _LOGGER = logging.getLogger(__name__)

    def get_scan_types(self):
        return ["IntSights Report"]

    def get_label_for_scan_types(self, scan_type):
        return "IntSights Report"

    def get_description_for_scan_types(self, scan_type):
        return "IntSights report file can be imported in JSON format."

    def _parse_assets(self, assets):
        """
        Parses the Assets node to create a string to be used in the Description
        """

        assets_affected = ''

        for entry in assets:
            assets_affected = f'{assets_affected} Type: {entry["Type"]}, Value: {entry["Value"]},'

        return assets_affected[:-1]

    def _get_alerts_from_file(self, file) -> []:
        """
        Parse Alerts from a JSON file compiled from the Threat Command API, or CSV file provided by the IntSights
        Threat Command GUI.

        Normalize the key/value pairs using the CSV keys as canonical.

        Args:
            file: The file object from the get_findings() method

        Returns:
            A list of IntSights alerts in dict format
        """
        alerts = []


        original_alerts = json.load(file)
        for original_alert in original_alerts['Alerts']:
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



    def _parse_json(self, json_file):
        """

        Args:
            json_file:

        Returns:

        """

    def _parse_csv(self, csv_file):
        """

        Args:
            csv_file:

        Returns:

        """
        # If JSON parsing fails, try CSV parsing
        default_keys = ['Alert ID', 'Title', 'Description', 'Severity', 'Type', 'Source Date (UTC)',
                        'Report Date (UTC)', 'Network Type', 'Source URL', 'Source Name', 'Assets', 'Tags',
                        'Assignees', 'Remediation', 'Status', 'Closed Reason', 'Additional Info', 'Rating',
                        'Alert Link']

        alerts = []

        file_content  = csv_file.read()
        if type(file_content) is bytes:
            file_content = file_content.decode('utf-8')

        csv_reader = csv.DictReader(io.StringIO(file_content), delimiter=',', quotechar='"')

        # Don't bother parsing if the keys don't match exactly what's expected
        if collections.Counter(default_keys) == collections.Counter(csv_reader.fieldnames):
            for alert in csv_reader:
                alert['alert_id'] = alert.pop('Alert ID')
                alert['title'] = alert.pop('Title')
                alert['description'] = alert.pop('Description')
                alert['severity'] = alert.pop('Severity')
                alert['type'] = alert.pop('Type')
                alert['source_date'] = alert.pop('Source Date (UTC)')
                alert['report_date'] = alert.pop('Report Date (UTC)')
                alert['network_type'] = alert.pop('Network Type')
                alert['source_url'] = alert.pop('Source URL')
                alert['assets'] = alert.pop('Assets')
                alert['tags'] = alert.pop('Tags')
                alert['status'] = alert.pop('Status')
                alert['alert_link'] = alert.pop('Alert Link')
                alert.pop('Assignees')
                alert.pop('Remediation')
                alert.pop('Closed Reason')
                alert.pop('Rating')
                alerts.append(alert)
        return alerts


    def get_findings(self, file, test):
        duplicates = dict()

        alerts = []

        if 'text/json' == file.content_type:
            alerts = self._parse_json(file)
        elif 'text/csv' == file.content_type:
            alerts = self._parse_csv(file)

        if not alerts:
            raise ValueError('IntSights report contains errors: No vulnerabilities were found in the data provided')

        for alert in alerts:
            dupe_key = alert['alert_id']

            if dupe_key in duplicates:
                alert = duplicates[dupe_key]
                duplicates[dupe_key] = alert
            else:
                duplicates[dupe_key] = True

                alert = Finding(title = alert['title'],
                                test = test,
                                active = False if alert['status'] == 'Closed' else True,
                                verified = True,
                                description = f'{alert["description"]}' \
                                              f'\n\n----' \
                                              f'\r\n**Date Found**: {alert["report_date"]}' \
                                              f'\n\n----' \
                                              f'\r\n**Type**: {alert["type"]}' \
                                              f'\r\n**Source**: {alert["source_url"]}' \
                                              f'\r\n**Source Date**: {alert["source_date"]}' \
                                              f'\r\n**Source Network Type**: {alert["network_type"]}' \
                                              f'\n\n----' \
                                              f'\r\n**Assets Affected**: {alert["assets"]}' \
                                              f'\n\n----' \
                                              f'\r\n**Alert Link**: {alert["alert_link"]}',
                                severity = alert['severity'],
                                references = alert["alert_link"],
                                static_finding = False,
                                dynamic_finding = True,
                                unique_id_from_tool = alert['alert_id'])
                duplicates[dupe_key] = alert

        return duplicates.values()
