import datetime
import io
import re
from unittest import mock
from xml.etree import ElementPath

from django.test import override_settings

from dojo.models import Test
from dojo.tools.qualys.parser import QualysParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def _report_with_hosts(count):
    """The sample report with its hosts repeated to ``count`` hosts, each with its own address."""
    sample = (get_unit_tests_scans_path("qualys") / "Qualys_Sample_Report.xml").read_text(encoding="utf-8")
    head, rest = sample.split("<HOST_LIST>", 1)
    hosts, tail = rest.split("</HOST_LIST>", 1)
    blocks = re.findall(r"<HOST>.*?</HOST>", hosts, flags=re.DOTALL)
    repeated = [
        re.sub(r"<IP>[^<]*</IP>", f"<IP>192.0.2.{index + 1}</IP>", blocks[index % len(blocks)], count=1)
        for index in range(count)
    ]
    return _named(f"{head}<HOST_LIST>{''.join(repeated)}</HOST_LIST>{tail}")


def _named(content):
    report = io.BytesIO(content.encode())
    report.name = "report.xml"
    return report


class TestQualysParser(DojoTestCase):

    def test_glossary_is_searched_once_per_report_not_once_per_finding(self):
        # Every finding used to look its QID up with a search from the document root, which walks
        # all the hosts before it reaches the glossary: the parse was findings x document size.
        # Every find, findall, findtext and iterfind, on an element or on the whole tree, resolves its
        # path through ElementPath.iterfind, so a per-QID lookup from any starting point is counted.
        searches = []
        original = ElementPath.iterfind

        def counting(elem, path, namespaces=None):
            if "VULN_DETAILS" in path:
                searches.append(path)
            return original(elem, path, namespaces)

        patcher = mock.patch.object(ElementPath, "iterfind", counting)
        patcher.start()
        self.addCleanup(patcher.stop)

        small = QualysParser().get_findings(_report_with_hosts(2), Test())
        small_searches = len(searches)
        searches.clear()
        large = QualysParser().get_findings(_report_with_hosts(14), Test())

        self.assertGreater(len(large), len(small))
        self.assertEqual(small_searches, len(searches))

    def test_repeated_glossary_entry_keeps_the_first(self):
        sample = (get_unit_tests_scans_path("qualys") / "Qualys_Sample_Report.xml").read_text(encoding="utf-8")
        details = re.search(r"<VULN_DETAILS id=\"qid_6\">.*?</VULN_DETAILS>", sample, flags=re.DOTALL).group(0)
        shadow = re.sub(r"<TITLE><!\[CDATA\[[^\]]*\]\]></TITLE>", "<TITLE><![CDATA[Shadowed]]></TITLE>", details, count=1)
        report = _named(sample.replace("</VULN_DETAILS_LIST>", f"{shadow}</VULN_DETAILS_LIST>", 1))

        titles = {finding.title for finding in QualysParser().get_findings(report, Test())}

        self.assertIn("QID-6 | DNS Host Name", titles)
        self.assertNotIn("QID-6 | Shadowed", titles)

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_no_vuln_has_no_findings_first_seen(self):
        self.parse_file_with_no_vuln_has_no_findings()

    def test_parse_file_with_no_vuln_has_no_findings(self):
        self.parse_file_with_no_vuln_has_no_findings()

    def parse_file_with_no_vuln_has_no_findings(self):
        with (
            get_unit_tests_scans_path("qualys") / "empty.xml").open(encoding="utf-8",
        ) as testfile:
            parser = QualysParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_multiple_vuln_has_multiple_findings_first_seen(self):
        finding = self.parse_file_with_multiple_vuln_has_multiple_findings()
        self.assertEqual(datetime.datetime(2019, 7, 31).date(), finding.date)

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        finding = self.parse_file_with_multiple_vuln_has_multiple_findings()
        self.assertEqual(datetime.datetime(2019, 7, 31).date(), finding.date)

    def parse_file_with_multiple_vuln_has_multiple_findings(self):
        with (
            get_unit_tests_scans_path("qualys") / "Qualys_Sample_Report.xml").open(encoding="utf-8",
        ) as testfile:
            parser = QualysParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            self.assertEqual(301, len(findings))

            finding = findings[0]
            self.assertEqual(
                finding.title, "QID-6 | DNS Host Name",
            )
            self.assertEqual(
                finding.severity, "Info",
            )
            self.assertEqual(
                self.get_unsaved_locations(finding)[0].host, "demo13.s02.sjc01.qualys.com",
            )
            for finding in findings:
                if self.get_unsaved_locations(finding)[0].host == "demo14.s02.sjc01.qualys.com" and finding.title == "QID-370876 | AMD Processors Multiple Security Vulnerabilities (RYZENFALL/MASTERKEY/CHIMERA-FW/FALLOUT)":
                    finding_cvssv3_score = finding
                if self.get_unsaved_locations(finding)[0].host == "demo13.s02.sjc01.qualys.com" and finding.title == "QID-370876 | AMD Processors Multiple Security Vulnerabilities (RYZENFALL/MASTERKEY/CHIMERA-FW/FALLOUT)":
                    finding_cvssv3_vector = finding
            self.assertEqual(
                # CVSS_FINAL is defined without a cvssv3 vector
                finding_cvssv3_score.cvssv3, None,
            )
            self.assertEqual(
                finding_cvssv3_score.severity, "High",
            )
            self.assertEqual(finding_cvssv3_vector.cvssv3,
                            "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H")
            self.assertEqual(
                finding_cvssv3_vector.severity, "High",
            )
            return finding

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_no_vuln_has_no_findings_csv_first_seen(self):
        self.parse_file_with_no_vuln_has_no_findings_csv()

    def test_parse_file_with_no_vuln_has_no_findings_csv(self):
        self.parse_file_with_no_vuln_has_no_findings_csv()

    def parse_file_with_no_vuln_has_no_findings_csv(self):
        with (
            get_unit_tests_scans_path("qualys") / "empty.csv").open(encoding="utf-8",
        ) as testfile:
            parser = QualysParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            self.assertEqual(0, len(findings))

    def test_finding_with_missing_glossary_entry_is_skipped(self):
        # A QID that matches no GLOSSARY VULN_DETAILS has neither severity nor title to
        # import; the parser used to raise AttributeError on it and abort the whole import.
        sample = (get_unit_tests_scans_path("qualys") / "Qualys_Sample_Report.xml").read_text(encoding="utf-8")
        without_qid_6_entry = re.sub(
            r"<VULN_DETAILS id=\"qid_6\">.*?</VULN_DETAILS>",
            "",
            sample,
            count=1,
            flags=re.DOTALL,
        )
        report = io.BytesIO(without_qid_6_entry.encode())
        report.name = "report.xml"

        with self.assertLogs("dojo.tools.qualys.parser", level="WARNING") as logged:
            findings = QualysParser().get_findings(report, Test())

        # Seven findings report QID 6 in the full sample's 301; each is skipped
        # while everything else still imports.
        self.validate_locations(findings)
        self.assertEqual(294, len(findings))
        titles = {finding.title for finding in findings}
        self.assertNotIn("QID-6 | DNS Host Name", titles)
        self.assertTrue(any("qid_6" in message for message in logged.output))

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_multiple_vuln_has_multiple_findings_csv_first_seen(self):
        finding = self.parse_file_with_multiple_vuln_has_multiple_findings_csv()
        self.assertEqual(datetime.datetime(2021, 5, 13).date(), finding.date)

    def test_parse_file_with_multiple_vuln_has_multiple_findings_csv(self):
        finding = self.parse_file_with_multiple_vuln_has_multiple_findings_csv()
        self.assertEqual(datetime.datetime(2021, 5, 25).date(), finding.date)

    def parse_file_with_multiple_vuln_has_multiple_findings_csv(self):
        with (
            get_unit_tests_scans_path("qualys") / "Qualys_Sample_Report.csv").open(encoding="utf-8",
        ) as testfile:
            parser = QualysParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            self.assertEqual(3, len(findings))

            finding = findings[0]
            self.assertEqual(
                finding.title,
                "QID-105971 | EOL/Obsolete Software: Microsoft ASP.NET 1.0 Detected")
            self.assertEqual(
                finding.severity, "Critical",
            )
            self.assertEqual(
                self.get_unsaved_locations(finding)[0].host, "ip-10-98-57-180.eu-west-1.compute.internal",
            )

            for finding in findings:
                if self.get_unsaved_locations(finding)[0].host == "ip-10-98-57-180.eu-west-1.compute.internal" and finding.title == "QID-105971 | EOL/Obsolete Software: Microsoft ASP.NET 1.0 Detected":

                    self.assertEqual(
                        finding.severity, "Critical",
                    )
                    self.assertEqual(
                        finding.cvssv3,
                        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:U/RC:C")
                    self.assertEqual(
                        finding.severity, "Critical",
                    )

            return findings[0]

    def test_parse_file_monthly_pci_issue6932(self):
        with (
            get_unit_tests_scans_path("qualys") / "monthly_pci_issue6932.csv").open(encoding="utf-8",
        ) as testfile:
            parser = QualysParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            self.assertEqual(1, len(findings))

    def test_parse_file_with_cvss_values_and_scores(self):
        with (
            get_unit_tests_scans_path("qualys") / "Qualys_Sample_Report.xml").open(encoding="utf-8",
        ) as testfile:
            parser = QualysParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            for finding in findings:
                if self.get_unsaved_locations(finding)[0].host == "demo14.s02.sjc01.qualys.com" and finding.title == "QID-370876 | AMD Processors Multiple Security Vulnerabilities (RYZENFALL/MASTERKEY/CHIMERA-FW/FALLOUT)":
                    finding_cvssv3_score = finding
                    self.assertEqual(
                        finding.unsaved_vulnerability_ids,
                        [
                            "CVE-2018-8930",
                            "CVE-2018-8931",
                            "CVE-2018-8932",
                            "CVE-2018-8933",
                            "CVE-2018-8934",
                            "CVE-2018-8935",
                            "CVE-2018-8936",
                        ],
                    )
                if self.get_unsaved_locations(finding)[0].host == "demo13.s02.sjc01.qualys.com" and finding.title == "QID-370876 | AMD Processors Multiple Security Vulnerabilities (RYZENFALL/MASTERKEY/CHIMERA-FW/FALLOUT)":
                    finding_no_cvssv3_at_detection = finding
                    self.assertEqual(
                        finding.unsaved_vulnerability_ids,
                        [
                            "CVE-2018-8930",
                            "CVE-2018-8931",
                            "CVE-2018-8932",
                            "CVE-2018-8933",
                            "CVE-2018-8934",
                            "CVE-2018-8935",
                            "CVE-2018-8936",
                        ],
                    )
                if self.get_unsaved_locations(finding)[0].host == "demo14.s02.sjc01.qualys.com" and finding.title == 'QID-121695 | NTP "monlist"  Feature Denial of Service Vulnerability':
                    finding_no_cvssv3 = finding
                    self.assertEqual(
                        finding.unsaved_vulnerability_ids,
                        ["CVE-2013-5211"],
                    )
            # The CVSS Vector is not used from the Knowledgebase
            self.assertEqual(
                # CVSS_FINAL is defined without a cvssv3 vector
                finding_cvssv3_score.cvssv3, None,
            )
            # Nevertheless the CVSSv3 Score should be set
            self.assertEqual(
                finding_cvssv3_score.cvssv3_score, 8.2,
            )
            # If no cvss information is present in detection and not in knowledgebase values should be empty
            self.assertEqual(
                finding_no_cvssv3.cvssv3, None,
            )
            self.assertEqual(
                finding_no_cvssv3.cvssv3_score, None,
            )
            # No CVSS Values available in detection and it uses the knowledgebase then
            self.assertEqual(finding_no_cvssv3_at_detection.cvssv3,
                            "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H")
            self.assertEqual(
                finding_no_cvssv3_at_detection.cvssv3_score, 9.0,
            )

    def test_get_severity_legacy(self):
        with (get_unit_tests_scans_path("qualys") / "Qualys_Sample_Report.xml").open(encoding="utf-8") as testfile:
            parser = QualysParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            counts = {}
            for finding in findings:
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
            expected_counts = {
                "Info": 177,
                "Low": 65,
                "Medium": 46,
                "High": 6,
                "Critical": 7,
            }

            self.assertEqual(expected_counts, counts)

    @override_settings(USE_QUALYS_LEGACY_SEVERITY_PARSING=False)
    def test_get_severity(self):
        with (get_unit_tests_scans_path("qualys") / "Qualys_Sample_Report.xml").open(encoding="utf-8") as testfile:
            parser = QualysParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            counts = {}
            for finding in findings:
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
            expected_counts = {
                "Low": 242,
                "Medium": 46,
                "High": 13,
            }

            self.assertEqual(expected_counts, counts)
