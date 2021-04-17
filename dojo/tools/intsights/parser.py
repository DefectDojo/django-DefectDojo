import json

from dojo.models import Finding


class IntSightsParser(object):
    """
    IntSights Threat Intelligence Feed
    """

    def get_scan_types(self):
        return ["IntSights Report"]

    def get_label_for_scan_types(self, scan_type):
        return "IntSights Report"

    def get_description_for_scan_types(self, scan_type):
        return "IntSights report file can be imported in JSON format."

    def _parser_assets(self, assets):
        """
        Parses the Assets node to create a string to be used in the Description
        """

        assets_affected = ''

        for entry in assets:
            assets_affected = f'{assets_affected} Type: {entry["Type"]}, Value: {entry["Value"]},'

        return assets_affected[:-1]

    def get_findings(self, file, test):
        duplicates = dict()

        if not file:
            return []

        data = file.read()

        try:
            findings = json.loads(str(data, 'utf-8'))
        except:
            findings = json.loads(data)

        if not findings:
            raise ValueError('IntSights report contains errors: No vulnerabilities were found in the data provided')

        if findings.get('Findings'):
            for finding in findings['Findings']:
                unique_id_from_tool = finding['_id']
                title = finding['Details']['Title']

                assets_affected = self._parser_assets(finding['Assets'])

                description = f'{finding["Details"]["Description"]}' \
                              f'\r\n\r\n----' \
                              f'\r\n**Date Found**: {finding.get("FoundDate", "None provided")}' \
                              f'\r\n**Date Updated**: {finding.get("UpdateDate", "None provided")}' \
                              f'\r\n\r\n----' \
                              f'\r\n\r\n**Type**: {finding["Details"]["Type"]}' \
                              f'\r\n**SubType**: {finding["Details"]["SubType"]}' \
                              f'\r\n**Source**: {finding["Details"]["Source"].get("URL", "None provided")}' \
                              f'\r\n**Source Date**: {finding["Details"]["Source"].get("Date", "None provided")}' \
                              f'\r\n**Source Type**: {finding["Details"]["Source"].get("URL", "N/A")}' \
                              f'\r\n**Source Network Type**: {finding["Details"]["Source"].get("NetworkType", "N/A")}' \
                              f'\r\n\r\n----' \
                              f'\r\n**Assets Affected**: {assets_affected}' \
                              f'\r\n\r\n----' \
                              f'\r\n**Takedown Status**: {finding["TakedownStatus"]}'
                severity = finding['Details']['Severity']
                mitigation = "N/A"
                impact = "N/A"
                references = finding["Details"]["Source"].get("URL", "")
                active = False if finding['Closed']['IsClosed'] else True

                dupe_key = finding['_id']

                if dupe_key in duplicates:
                    finding = duplicates[dupe_key]
                    duplicates[dupe_key] = finding
                else:
                    duplicates[dupe_key] = True

                    finding = Finding(title = title,
                                      test = test,
                                      active = active,
                                      verified = True,
                                      description = description,
                                      severity = severity,
                                      numerical_severity = Finding.get_numerical_severity(severity),
                                      mitigation = mitigation,
                                      impact = impact,
                                      references = references,
                                      static_finding = False,
                                      dynamic_finding = True,
                                      unique_id_from_tool = unique_id_from_tool)
                    duplicates[dupe_key] = finding

            return duplicates.values()
        else:
            return []
