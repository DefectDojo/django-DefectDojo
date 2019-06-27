from abc import ABC, abstractmethod
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Mapping, Set, Tuple
from dojo.tools.blackduck.model import BlackduckFinding
import csv
import io
import zipfile


class Importer(ABC):
    @abstractmethod
    def parse_findings(self, report: Path) -> Iterable[BlackduckFinding]:
        while False:
            yield None


class BlackduckImporter(Importer):
    def parse_findings(self, report: Path) -> Iterable[BlackduckFinding]:
        files = dict()
        security_issues = dict()
        if zipfile.is_zipfile(report):
            with zipfile.ZipFile(report) as zip:
                for file_name in zip.namelist():
                    if file_name.endswith('files.csv'):
                        with io.TextIOWrapper(zip.open(file_name), newline='') as f:
                            files = self.__partition_by_project_id(f)
                    elif file_name.endswith('security.csv'):
                        with io.TextIOWrapper(zip.open(file_name), newline='') as f:
                            security_issues = self.__partition_by_project_id(f)
        else:
            raise ValueError

        project_ids = set(files.keys()) & set(security_issues.keys())
        for project_id in project_ids:
            locations = set()
            for file_entry in files[project_id]:
                path = file_entry[8]
                archive_context = file_entry[9]
                if archive_context:
                    locations.add(f"{archive_context}{path[1:]}")
                else:
                    locations.add(path)
            for issue in security_issues[project_id]:
                yield BlackduckFinding(
                    issue[8],  # vuln ID
                    issue[9],  # description
                    issue[21],  # security_risk
                    issue[14],  # impact
                    issue[15],  # vulnerability source
                    issue[20],  # url
                    issue[6],  # channel version origin id
                    issue[10],  # published date
                    issue[11],  # updated on
                    issue[12],  # base score
                    issue[13],  # exploitability
                    issue[16],  # remediation status
                    issue[17],  # remediation target date
                    issue[18],  # remediation actual date
                    issue[19],  # remediation comment
                    ', '.join([location for location in locations])
                )

    def __partition_by_project_id(self, csv_file) -> Mapping[str, Set[Tuple[str]]]:
        records = csv.reader(csv_file)
        next(csv_file)
        findings = defaultdict(set)
        for record in records:
            findings[record[0]].add(tuple(record))
        return findings
