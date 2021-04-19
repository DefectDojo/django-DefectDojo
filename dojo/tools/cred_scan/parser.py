import csv
import io
from datetime import datetime


from dojo.models import Finding


class CredScanParser(object):

    def get_scan_types(self):
        return ["CredScan Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "CredScan Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import CSV output of CredScan scan report."

    def get_findings(self, filename, test):
        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8-sig')
        reader = csv.DictReader(io.StringIO(content), delimiter=',', quotechar='"')

        dupes = dict()
        for row in reader:
            # Severity is not provided in this scanner, so marking all as info
            severity = 'Info'

            # Create the description
            description = row.get('Description', 'Description not provided')
            is_suppressed = row.get('IsSuppressed', None)
            supress_justification = row.get('SuppressJustification', None)
            matching_score = row.get('MatchingScore', None)
            date = row.get('TimeofDiscovery', None)

            # Add contextual details to the description
            if is_suppressed:
                description += '\n Is Supressed: ' + str(is_suppressed)
            if supress_justification:
                description += '\n Supress Justifcation: ' + str(supress_justification)
            if matching_score:
                description += '\n Matching Score: ' + str(matching_score)

            finding = Finding(
                    title=row.get('Searcher'),
                    description=description,
                    severity=severity,
                    nb_occurences=1,
                    file_path=row.get('Source'),
                    line=row.get('Line'),
            )
            # Update the finding date if it specified
            if date:
                finding.date = datetime.strptime(date.replace('Z', ''), '%Y-%m-%dT%H:%M:%S.%f')

            # internal de-duplication
            dupe_key = row.get('Searcher') + row.get('Source') + str(row.get('Line'))

            if dupe_key in dupes:
                find = dupes[dupe_key]
                find.nb_occurences += finding.nb_occurences
            else:
                dupes[dupe_key] = finding

        return list(dupes.values())
