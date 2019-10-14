
from abc import ABC, abstractmethod
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Union
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
        if not issubclass(type(report), Path):
            report = Path(report.temporary_file_path())

        files = dict()
        security_issues = dict()
        try:
            if zipfile.is_zipfile(str(report)):
                with zipfile.ZipFile(str(report)) as zip:
                    for file_name in zip.namelist():
                        if file_name.endswith('files.csv'):
                            with io.TextIOWrapper(zip.open(file_name)) as f:
                                files = self.__partition_by_project_id(f)
                        elif file_name.endswith('security.csv'):
                            with io.TextIOWrapper(zip.open(file_name)) as f:
                                security_issues = self.__partition_by_project_id(f)
            else:
                print("Not a zip file?")
                raise ValueError
        except Exception as e:
            print("Could not process zip file: {}".format(e))

        project_ids = set(files.keys()) & set(security_issues.keys())
        for project_id in project_ids:
            locations = set()
            for file_entry in files[project_id]:
                file_entry_dict = dict(file_entry)
                path = file_entry_dict.get('Path')
                archive_context = file_entry_dict.get('Archive context')
                if archive_context:
                    locations.add("{}{}".format(archive_context, path[1:]))
                else:
                    locations.add(path)
            for issue in security_issues[project_id]:
                security_issue_dict = dict(issue)
                yield BlackduckFinding(
                    security_issue_dict.get('Vulnerability id'),
                    security_issue_dict.get('Description'),
                    security_issue_dict.get('Security Risk'),
                    security_issue_dict.get('Impact'),
                    security_issue_dict.get('Vulnerability source'),
                    security_issue_dict.get('URL'),
                    security_issue_dict.get('Channel version origin id'),
                    security_issue_dict.get('Channel origin id'),
                    security_issue_dict.get('Published on'),
                    security_issue_dict.get('Updated on'),
                    security_issue_dict.get('Base score'),
                    security_issue_dict.get('Exploitability'),
                    security_issue_dict.get('Remediation status'),
                    security_issue_dict.get('Remediation target date'),
                    security_issue_dict.get('Remediation actual date'),
                    security_issue_dict.get('Remediation comment'),
                    ', '.join(locations)
                )

    # return type elided due to higher kinded types bug in Python 3.5
    def __partition_by_project_id(self, csv_file: Union[Path, zipfile.ZipFile]):
        records = csv.DictReader(csv_file)
        findings = defaultdict(set)
        for record in records:
            findings[record.get('Project id')].add(frozenset(record.items()))
        return findings
