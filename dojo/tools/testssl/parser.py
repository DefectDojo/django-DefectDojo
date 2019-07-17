import io
import csv
import hashlib
from dojo.models import Finding

__author__ = 'dr3dd589'


class TestsslCSVParser(object):
    def __init__(self, filename, test):
        self.dupes = dict()
        self.items = ()

        if filename is None:
            self.items = ()
            return

        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        reader = csv.DictReader(io.StringIO(content), delimiter=',', quotechar='"')
        csvarray = []

        for row in reader:
            csvarray.append(row)

        for row in csvarray:
            if 'OK' not in row['severity']:
                finding = Finding(test=test)
                finding.title = row['Title'] if row['Title'][0] != "'" else row['Title'][1:]
                if finding is not None:
                    if finding.title is None:
                        finding.title = ""
                    if finding.description is None:
                        finding.description = ""

                    key = hashlib.md5((finding.title + '|' + finding.description).encode("utf-8")).hexdigest()

                    if key not in self.dupes:
                        self.dupes[key] = finding

            self.items = list(self.dupes.values())
