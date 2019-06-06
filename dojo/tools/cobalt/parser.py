import io
import csv
import hashlib
from dojo.models import Finding

__author__ = 'dr3dd589'


class CobaltCSVParser(object):
    def __init__(self, filename, test):
        self.dupes = dict()
        self.items = ()

        if filename is None:
            self.items = ()
            return

        content = filename.read()
        reader = csv.DictReader(io.StringIO(content), delimiter=',', quotechar='"')
        csvarray = []

        for row in reader:
            csvarray.append(row)

        for row in csvarray:
            finding = Finding(test=test)
            finding.title = row['Title']
            finding.description = "**Type** : " + row['Type'] + "\n\n" + \
                                "**Description** : " + row['Description'] + "\n"
            finding.mitigation = row['SuggestedFix']
            finding.references = row['ResearcherUrl']
            finding.steps_to_reproduce = row['StepsToReproduce']
            finding.severity_justification = row['CriticalityJustification']
            finding.severity = "Info"

            if finding is not None:
                if finding.title is None:
                    finding.title = ""
                if finding.description is None:
                    finding.description = ""

                key = hashlib.md5(finding.title + '|' + finding.description).hexdigest()

                if key not in self.dupes:
                    self.dupes[key] = finding

        self.items = list(self.dupes.values())
