import StringIO
import csv
import hashlib
from dojo.models import Finding
from dateutil.parser import parse


class ColumnMappingStrategy(object):
    def __init__(self):
        self.successor = None

    def process_column(self, column_name, column_value, finding):
        pass


class DateColumnMappingStrategy(ColumnMappingStrategy):

    def process_column(self, column_name, column_value, finding):

        if column_name.lower() == 'date' and column_value is not None:
            finding.date = parse(column_value).date()
        elif self.successor is not None:
            self.successor.process_column(column_name, column_value, finding)


class TitleColumnMappingStrategy(ColumnMappingStrategy):

    def process_column(self, column_name, column_value, finding):
        if column_name.lower() == 'title' and column_value is not None:
            finding.title = column_value
        elif self.successor is not None:
            self.successor.process_column(column_name, column_value, finding)


class CweColumnMappingStrategy(ColumnMappingStrategy):

    def process_column(self, column_name, column_value, finding):
        if column_name.lower() == 'cweid' and column_value is not None:
            if column_value.isdigit():
                finding.cwe = int(column_value)
        elif self.successor is not None:
            self.successor.process_column(column_name, column_value, finding)


class UrlColumnMappingStrategy(ColumnMappingStrategy):

    def process_column(self, column_name, column_value, finding):
        if column_name.lower() == 'url' and column_value is not None:
            finding.url = column_value
        elif self.successor is not None:
            self.successor.process_column(column_name, column_value, finding)


class SeverityColumnMappingStrategy(ColumnMappingStrategy):

    @staticmethod
    def is_valid_severity(severity):
        valid_severity = ('Info', 'Low', 'Medium', 'High', 'Critical')
        return severity in valid_severity

    def process_column(self, column_name, column_value, finding):
        if column_name.lower() == 'severity' and column_value is not None:
            if self.is_valid_severity(column_value):
                finding.severity = column_value
            else:
                finding.severity = 'Info'
        elif self.successor is not None:
            self.successor.process_column(column_name, column_value, finding)


class DescriptionColumnMappingStrategy(ColumnMappingStrategy):

    def process_column(self, column_name, column_value, finding):
        if column_name.lower() == 'description' and column_value is not None:
            finding.description = column_value
        elif self.successor is not None:
            self.successor.process_column(column_name, column_value, finding)


class MitigationColumnMappingStrategy(ColumnMappingStrategy):

    def process_column(self, column_name, column_value, finding):
        if column_name.lower() == 'mitigation' and column_value is not None:
            finding.mitigation = column_value
        elif self.successor is not None:
            self.successor.process_column(column_name, column_value, finding)


class ImpactColumnMappingStrategy(ColumnMappingStrategy):

    def process_column(self, column_name, column_value, finding):
        if column_name.lower() == 'impact' and column_value is not None:
            finding.impact = column_value
        elif self.successor is not None:
            self.successor.process_column(column_name, column_value, finding)


class ReferencesColumnMappingStrategy(ColumnMappingStrategy):

    def process_column(self, column_name, column_value, finding):
        if column_name.lower() == 'references' and column_value is not None:
            finding.references = column_value
        elif self.successor is not None:
            self.successor.process_column(column_name, column_value, finding)


class ActiveColumnMappingStrategy(ColumnMappingStrategy):

    def process_column(self, column_name, column_value, finding):
        if column_name.lower() == 'active' and column_value is not None:
            if column_value.lower() == 'true':
                finding.active = True
            elif column_value.lower() == 'false':
                finding.active = False
        elif self.successor is not None:
            self.successor.process_column(column_name, column_value, finding)


class VerifiedColumnMappingStrategy(ColumnMappingStrategy):

    def process_column(self, column_name, column_value, finding):
        if column_name.lower() == 'verified' and column_value is not None:
            if column_value.lower() == 'true':
                finding.verified = True
            elif column_value.lower() == 'false':
                finding.verified = False
        elif self.successor is not None:
            self.successor.process_column(column_name, column_value, finding)


class FalsePositiveColumnMappingStrategy(ColumnMappingStrategy):

    def process_column(self, column_name, column_value, finding):
        if column_name.lower() == 'falsepositive' and column_value is not None:
            if column_value.lower() == 'true':
                finding.false_p = True
            elif column_value.lower() == 'false':
                finding.false_p = False
        elif self.successor is not None:
            self.successor.process_column(column_name, column_value, finding)


class DuplicateColumnMappingStrategy(ColumnMappingStrategy):

    def process_column(self, column_name, column_value, finding):
        if column_name.lower() == 'duplicate' and column_value is not None:
            if column_value.lower() == 'true':
                finding.duplicate = True
            elif column_value.lower() == 'false':
                finding.duplicate = False
        elif self.successor is not None:
            self.successor.process_column(column_name, column_value, finding)


class GenericFindingUploadCsvParser(object):

    def create_chain(self):
        date_column_strategy = DateColumnMappingStrategy()
        title_column_strategy = TitleColumnMappingStrategy()
        cwe_column_strategy = CweColumnMappingStrategy()
        url_column_strategy = UrlColumnMappingStrategy()
        severity_column_strategy = SeverityColumnMappingStrategy()
        description_column_strategy = DescriptionColumnMappingStrategy()
        mitigation_column_strategy = MitigationColumnMappingStrategy()
        impact_column_strategy = ImpactColumnMappingStrategy()
        references_column_strategy = ReferencesColumnMappingStrategy()
        active_column_strategy = ActiveColumnMappingStrategy()
        verified_column_strategy = VerifiedColumnMappingStrategy()
        false_positive_strategy = FalsePositiveColumnMappingStrategy()
        duplicate_strategy = DuplicateColumnMappingStrategy()

        false_positive_strategy.successor = duplicate_strategy
        verified_column_strategy.successor = false_positive_strategy
        active_column_strategy.successor = verified_column_strategy
        references_column_strategy.successor = active_column_strategy
        impact_column_strategy.successor = references_column_strategy
        mitigation_column_strategy.successor = impact_column_strategy
        description_column_strategy.successor = mitigation_column_strategy
        severity_column_strategy.successor = description_column_strategy
        url_column_strategy.successor = severity_column_strategy
        cwe_column_strategy.successor = url_column_strategy
        title_column_strategy.successor = cwe_column_strategy
        date_column_strategy.successor = title_column_strategy

        self.chain = date_column_strategy

    def read_column_names(self, row):
        index = 0
        for column in row:
            self.column_names[index] = column
            index += 1

    def __init__(self, filename, test):
        self.chain = None
        self.column_names = dict()
        self.dupes = dict()
        self.items = ()
        self.create_chain()

        if filename is None:
            self.items = ()
            return

        content = filename.read()

        row_number = 0
        reader = csv.reader(StringIO.StringIO(content), delimiter=',', quotechar='"')
        for row in reader:
            finding = Finding(test=test)

            if row_number == 0:
                self.read_column_names(row)
                row_number += 1
                continue

            column_number = 0
            for column in row:
                self.chain.process_column(self.column_names[column_number], column, finding)
                column_number += 1

            if finding is not None:
                key = hashlib.md5(finding.severity + '|' + finding.title + '|' + finding.description).hexdigest()

                if key not in self.dupes:
                    self.dupes[key] = finding

            row_number += 1

        self.items = self.dupes.values()
