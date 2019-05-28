import StringIO
import csv
import hashlib
from dojo.models import Finding

__author__ = 'dr3dd589'


class Severityfilter():
    def __init__(self):
        self.severity_mapping = {'Normal': 'Info',
                                 'Low': 'Low',
                                 'Medium': 'Medium',
                                 'High': 'High',
                                 'Very High': 'Critical'
                                 }
        self.severity = None

    def eval_column(self, column_value):
        if column_value in self.severity_mapping.keys():
            self.severity = self.severity_mapping[column_value]
        else:
            self.severity = 'Info'


class KiuwanCSVParser(object):
    def __init__(self, filename, test):
        self.dupes = dict()
        self.items = ()

        if filename is None:
            self.items = ()
            return

        content = filename.read()
        reader = csv.DictReader(StringIO.StringIO(content), delimiter=',', quotechar='"')
        csvarray = []

        for row in reader:
            csvarray.append(row)

        for row in csvarray:
            finding = Finding(test=test)
            findingdict = {}
            severityfilter = Severityfilter()
            severityfilter.eval_column(row['Priority'])
            findingdict['severity'] = severityfilter.severity
            findingdict['title'] = row['Rule']
            findingdict['description'] = "**Source file** : " + row['Source file'] + "\n\n" + \
                                        "**Vulnerability type** : " + row['Vulnerability type'] + "\n\n" + \
                                        "**Status** : " + row['Status'] + "\n\n" + \
                                        "**CWE Scope** : " + row['CWE Scope'] + "\n\n" + \
                                        "**Line text** : " + row['Line text'] + "\n\n" + \
                                        "**Normative** : " + row['Normative'] + "\n\n" + \
                                        "**Line number** : " + row['Line number'] + "\n\n" + \
                                        "**Rule code** : " + row['Rule code'] + "\n\n" + \
                                        "**File** : " + row['File'] + "\n\n" + \
                                        "**Source line text** : " + row['Source line text'] + "\n\n" + \
                                        "**Source line number** : " + row['Source line number'] + "\n"

            finding.title = findingdict['title']
            finding.description = findingdict['description']
            finding.references = "Not provided!"
            finding.mitigation = "Not provided!"
            finding.severity = findingdict['severity']
            finding.static_finding = True
            try:
                finding.cwe = int(row['CWE'])
            except:
                pass

            if finding is not None:
                if finding.title is None:
                    finding.title = ""
                if finding.description is None:
                    finding.description = ""

                key = hashlib.md5(finding.severity + '|' + finding.title + '|' + finding.description).hexdigest()

                if key not in self.dupes:
                    self.dupes[key] = finding

        self.items = self.dupes.values()
