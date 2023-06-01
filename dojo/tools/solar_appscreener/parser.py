import csv
import io
from dojo.models import Finding


class SolarAppscreenerParser(object):
    """
    SAST scanner
    """

    def get_scan_types(self):
        return ["Solar Appscreener Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Solar Appscreener Scan Detailed_Results.csv"

    def get_description_for_scan_types(self, scan_type):
        return "Solar Appscreener report file can be imported in CSV format from Detailed_Results.csv."

    def get_findings(self, filename, test):

        if filename is None:
            return ()

        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        reader = csv.DictReader(io.StringIO(
            content), delimiter=',', quotechar='"')
        csvarray = []

        for row in reader:
            csvarray.append(row)

        items = list()
        for row in csvarray:
            finding = Finding(test=test)
            finding.title = row.get('Vulnerability', '')
            finding.description = row.get('Description', '')
            finding.mitigation = row.get('Recommendations')
            finding.references = row.get('Links')
            finding.severity = row.get('Severity Level', 'Info')
            finding.file_path = row.get('File')
            finding.sast_source_file_path = row.get('File')
            finding.line = row.get('Line')

            if finding.line:
                if not finding.line.isdigit():
                    finding.line = finding.line.split("-")[0]

                if finding.line:
                    finding.line = int(finding.line)
                else:
                    finding.line = 0

            finding.sast_source_line = finding.line

            if finding is not None:
                if finding.title is None:
                    finding.title = ""
                if finding.description is None:
                    finding.description = ""

            items.append(finding)

        return items
