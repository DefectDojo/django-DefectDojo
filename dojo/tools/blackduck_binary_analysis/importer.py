import csv
from abc import ABC, abstractmethod
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from .model import BlackduckBinaryAnalysisFinding


class Importer(ABC):
    @abstractmethod
    def parse_findings(self, report: Path) -> Iterable[BlackduckBinaryAnalysisFinding]:
        while False:
            yield None


class BlackduckBinaryAnalysisImporter(Importer):
    def parse_findings(self, report: Path) -> Iterable[BlackduckBinaryAnalysisFinding]:
        orig_report_name = Path(report.name)
        if not issubclass(type(report), Path):
            report = Path(report.temporary_file_path())

        return self._process_csvfile(report, orig_report_name)

    def _process_csvfile(self, report, orig_report_name):
        """
        If passed a CSV file, process.
        """
        vulnerabilities = dict()
        with open(str(report), "r") as f:
            vulnerabilities = self.__partition_by_key(f)

        sha1_hash_keys = set(vulnerabilities.keys())
        return self._process_vuln_results(
            sha1_hash_keys, report, orig_report_name, vulnerabilities
        )

    def _process_vuln_results(
        self, sha1_hash_keys, report, orig_report_name, vulnerabilities
    ):
        """
        Process findings for each project.
        """
        for sha1_hash_key in sha1_hash_keys:
            for vuln in vulnerabilities[sha1_hash_key]:
                vuln_dict = dict(vuln)

                yield BlackduckBinaryAnalysisFinding(
                    orig_report_name,
                    vuln_dict.get("Component"),
                    vuln_dict.get("Version"),
                    vuln_dict.get("Latest version"),
                    vuln_dict.get("CVE"),
                    vuln_dict.get("Matching type"),
                    vuln_dict.get("CVSS"),
                    vuln_dict.get("CVE publication date"),
                    vuln_dict.get("Object compilation date"),
                    vuln_dict.get("Object"),
                    vuln_dict.get("Object full path"),
                    vuln_dict.get("Object SHA1"),
                    vuln_dict.get("CVSS3"),
                    vuln_dict.get("CVSS vector (v2)"),
                    vuln_dict.get("CVSS vector (v3)"),
                    vuln_dict.get("Summary"),
                    vuln_dict.get("Distribution package"),
                    vuln_dict.get("CVSS (Distribution)"),
                    vuln_dict.get("CVSS3 (Distribution)"),
                    vuln_dict.get("Triage vectors"),
                    vuln_dict.get("Unresolving triage vectors"),
                    vuln_dict.get("Note type"),
                    vuln_dict.get("Note reason"),
                    vuln_dict.get("Vulnerability URL"),
                    vuln_dict.get("Missing exploit mitigations"),
                    vuln_dict.get("BDSA"),
                    vuln_dict.get("Version override type")
                )

    def __partition_by_key(self, csv_file):
        csv_results = csv.DictReader(csv_file, delimiter=',', quotechar='"')
        vulnerabilities = defaultdict(set)

        key = "Object SHA1"

        for csv_res in csv_results:
            vulnerabilities[csv_res.get(key)].add(frozenset(csv_res.items()))

        return vulnerabilities
