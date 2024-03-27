import csv
import hashlib
import io
import re
from dateutil.parser import parse
from dojo.models import Finding, Endpoint


class ColumnMappingStrategy(object):
    mapped_column = None

    def __init__(self):
        self.successor = None

    def map_column_value(self, finding, column_value):
        pass

    @staticmethod
    def evaluate_bool_value(column_value):
        if column_value.lower() == "true":
            return True
        elif column_value.lower() == "false":
            return False
        else:
            return None

    def process_column(self, column_name, column_value, finding):
        if (
            column_name.lower() == self.mapped_column
            and column_value is not None
        ):
            self.map_column_value(finding, column_value)
        elif self.successor is not None:
            self.successor.process_column(column_name, column_value, finding)


class DateColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "timestamp"
        super(DateColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        finding.date = parse(column_value).date()


class TitleColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "nvt name"
        super(TitleColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        finding.title = column_value


class CweColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "cweid"
        super(CweColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        if column_value.isdigit():
            finding.cwe = int(column_value)


class PortColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "port"
        super(PortColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        if column_value.isdigit():
            finding.unsaved_endpoints[0].port = int(column_value)


class CveColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "cves"
        super(CveColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        if column_value != "":
            if "," in column_value:
                finding.description += "\n**All CVEs:** " + str(column_value)
                for value in column_value.split(","):
                    finding.unsaved_vulnerability_ids.append(value)
            else:
                finding.unsaved_vulnerability_ids.append(column_value)


class NVDCVEColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "nvt oid"
        super(NVDCVEColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, column_value)
        for cve in cves:
            finding.unsaved_vulnerability_ids.append(cve)


class ProtocolColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "port protocol"
        super(ProtocolColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        if column_value:  # do not store empty protocol
            finding.unsaved_endpoints[0].protocol = column_value


class IpColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "ip"
        super(IpColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        if not finding.unsaved_endpoints[
            0
        ].host:  # process only if host is not already defined (by field hostname)
            finding.unsaved_endpoints[0].host = column_value


class HostnameColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "hostname"
        super(HostnameColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        if column_value:  # do not override IP if hostname is empty
            finding.unsaved_endpoints[0].host = column_value


class SeverityColumnMappingStrategy(ColumnMappingStrategy):
    @staticmethod
    def is_valid_severity(severity):
        valid_severity = ("Info", "Low", "Medium", "High", "Critical")
        return severity in valid_severity

    def __init__(self):
        self.mapped_column = "severity"
        super(SeverityColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        if self.is_valid_severity(column_value):
            finding.severity = column_value
        else:
            finding.severity = "Info"


class DescriptionColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "summary"
        super(DescriptionColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        finding.description = column_value


class MitigationColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "solution"
        super(MitigationColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        finding.mitigation = column_value


class ImpactColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "vulnerability insight"
        super(ImpactColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        finding.impact = column_value


class ReferencesColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "specific result"
        super(ReferencesColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        finding.references = column_value


class ActiveColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "active"
        super(ActiveColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        finding.active = self.evaluate_bool_value(column_value)


class VerifiedColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "verified"
        super(VerifiedColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        finding.verified = self.evaluate_bool_value(column_value)


class FalsePositiveColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "falsepositive"
        super(FalsePositiveColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        finding.false_p = self.evaluate_bool_value(column_value)


class DuplicateColumnMappingStrategy(ColumnMappingStrategy):
    def __init__(self):
        self.mapped_column = "duplicate"
        super(DuplicateColumnMappingStrategy, self).__init__()

    def map_column_value(self, finding, column_value):
        finding.duplicate = self.evaluate_bool_value(column_value)


class OpenVASCSVParser(object):
    def create_chain(self):
        date_column_strategy = DateColumnMappingStrategy()
        title_column_strategy = TitleColumnMappingStrategy()
        cwe_column_strategy = CweColumnMappingStrategy()
        ip_column_strategy = IpColumnMappingStrategy()
        hostname_column_strategy = HostnameColumnMappingStrategy()
        severity_column_strategy = SeverityColumnMappingStrategy()
        description_column_strategy = DescriptionColumnMappingStrategy()
        mitigation_column_strategy = MitigationColumnMappingStrategy()
        impact_column_strategy = ImpactColumnMappingStrategy()
        references_column_strategy = ReferencesColumnMappingStrategy()
        active_column_strategy = ActiveColumnMappingStrategy()
        verified_column_strategy = VerifiedColumnMappingStrategy()
        false_positive_strategy = FalsePositiveColumnMappingStrategy()
        duplicate_strategy = DuplicateColumnMappingStrategy()
        port_strategy = PortColumnMappingStrategy()
        protocol_strategy = ProtocolColumnMappingStrategy()
        cve_column_strategy = CveColumnMappingStrategy()
        nvd_cve_column_strategy = NVDCVEColumnMappingStrategy()
        port_strategy.successor = protocol_strategy
        duplicate_strategy.successor = port_strategy
        false_positive_strategy.successor = duplicate_strategy
        verified_column_strategy.successor = false_positive_strategy
        active_column_strategy.successor = verified_column_strategy
        references_column_strategy.successor = active_column_strategy
        impact_column_strategy.successor = references_column_strategy
        mitigation_column_strategy.successor = impact_column_strategy
        description_column_strategy.successor = mitigation_column_strategy
        severity_column_strategy.successor = description_column_strategy
        ip_column_strategy.successor = severity_column_strategy
        hostname_column_strategy.successor = ip_column_strategy
        cwe_column_strategy.successor = hostname_column_strategy
        title_column_strategy.successor = cwe_column_strategy
        cve_column_strategy.successor = title_column_strategy
        nvd_cve_column_strategy.successor = cve_column_strategy
        date_column_strategy.successor = nvd_cve_column_strategy
        return date_column_strategy

    def read_column_names(self, row):
        column_names = dict()
        index = 0
        for column in row:
            column_names[index] = column
            index += 1
        return column_names

    def get_findings(self, filename, test):
        column_names = dict()
        dupes = dict()
        chain = self.create_chain()
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        reader = csv.reader(io.StringIO(content), delimiter=",", quotechar='"')
        row_number = 0
        for row in reader:
            finding = Finding(test=test)
            finding.unsaved_vulnerability_ids = list()
            finding.unsaved_endpoints = [Endpoint()]
            if row_number == 0:
                column_names = self.read_column_names(row)
                row_number += 1
                continue
            column_number = 0
            for column in row:
                chain.process_column(
                    column_names[column_number], column, finding
                )
                column_number += 1
            if finding is not None and row_number > 0:
                if finding.title is None:
                    finding.title = ""
                if finding.description is None:
                    finding.description = ""
                key = hashlib.sha256(
                    (
                        str(finding.unsaved_endpoints[0])
                        + "|"
                        + finding.severity
                        + "|"
                        + finding.title
                        + "|"
                        + finding.description
                    ).encode("utf-8")
                ).hexdigest()
                if key not in dupes:
                    dupes[key] = finding
            row_number += 1
        return list(dupes.values())
