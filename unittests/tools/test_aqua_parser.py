from collections import Counter

from dojo.models import Test
from dojo.tools.aqua.parser import AquaParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAquaParser(DojoTestCase):
    def test_aqua_parser_has_no_finding(self):
        with (get_unit_tests_scans_path("aqua") / "no_vuln.json").open(encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_aqua_parser_has_one_finding(self):
        with (get_unit_tests_scans_path("aqua") / "one_vuln.json").open(encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("CVE-2019-14697 - musl (1.1.20-r4) ", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
            self.assertEqual("musl libc through 1.1.23 has an x87 floating-point stack adjustment imbalance, related to the math/i386/ directory. In some cases, use of this library could introduce out-of-bounds writes that are not present in an application's source code.", finding.description)
            self.assertEqual("1.1.20-r5", finding.mitigation)
            self.assertEqual(True, finding.fix_available)
            self.assertEqual("\nhttps://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2019-14697", finding.references)
            self.assertEqual("musl", finding.component_name)
            self.assertEqual("1.1.20-r4", finding.component_version)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2019-14697", finding.unsaved_vulnerability_ids[0])
            finding_severity_justification = """
Aqua severity classification: None
Aqua scoring system: CVSS V2
Aqua score: 7.5
Vendor score: 7.5
NVD v3 vectors: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
NVD v2 vectors: AV:N/AC:L/Au:N/C:P/I:P/A:P
Aqua severity (high) used for classification.
"""
            self.assertEqual(finding_severity_justification, finding.severity_justification)

    def test_aqua_parser_has_many_findings(self):
        with (get_unit_tests_scans_path("aqua") / "many_vulns.json").open(encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(24, len(findings))

    def test_aqua_parser_v2_has_one_finding(self):
        with (get_unit_tests_scans_path("aqua") / "one_v2.json").open(encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("CVE-2019-15601: curl", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("CURL before 7.68.0 lacks proper input validation, which allows users to create a `FILE:` URL that can make the client access a remote file using SMB (Windows-only issue).", finding.description)
            self.assertEqual("Upgrade to curl 7.68.0", finding.mitigation)
            self.assertEqual(True, finding.fix_available)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2019-15601", finding.unsaved_vulnerability_ids[0])

    def test_aqua_parser_v2_has_many_findings(self):
        with (get_unit_tests_scans_path("aqua") / "many_v2.json").open(encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

    def test_aqua_parser_cvssv3_has_no_finding(self):
        with (get_unit_tests_scans_path("aqua") / "many_v2.json").open(encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            nb_cvssv3 = 0
            for finding in findings:
                if finding.cvssv3 is not None:
                    nb_cvssv3 += 1

            self.assertEqual(0, nb_cvssv3)

    def test_aqua_parser_cvssv3_has_many_findings(self):
        with (get_unit_tests_scans_path("aqua") / "many_vulns.json").open(encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            nb_cvssv3 = 0
            for finding in findings:
                if finding.cvssv3 is not None:
                    nb_cvssv3 += 1

            self.assertEqual(16, nb_cvssv3)

    def test_aqua_parser_for_aqua_severity(self):
        with (get_unit_tests_scans_path("aqua") / "vulns_with_aqua_severity.json").open(encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())

            sevs = [finding.severity for finding in findings]

            d = Counter(sevs)
            self.assertEqual(1, d["Critical"])
            self.assertEqual(1, d["High"])
            self.assertEqual(2, d["Medium"])
            self.assertEqual(2, d["Low"])
            self.assertEqual(7, d["Info"])

    def test_aqua_parser_issue_10585(self):
        with (get_unit_tests_scans_path("aqua") / "issue_10585.json").open(encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_aqua_parser_aqua_devops_issue_10611(self):
        with (get_unit_tests_scans_path("aqua") / "aqua_devops_issue_10611.json").open(encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(101, len(findings))
            self.assertEqual("server.key - server.key (/juice-shop/node_modules/node-gyp/test/fixtures/server.key) ", findings[83].title)

    def test_aqua_parser_aqua_devops_issue_10849(self):
        with (get_unit_tests_scans_path("aqua") / "issue_10849.json").open(encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0.0006, findings[0].epss_score)
            self.assertEqual(0.23474, findings[0].epss_percentile)

    def test_aqua_parser_aqua_devops_empty(self):
        with (get_unit_tests_scans_path("aqua") / "empty_aquadevops.json").open(encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_aqua_parser_over_api_v2(self):
        with (get_unit_tests_scans_path("aqua") / "over_api_v2.json").open(encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(99, len(findings))

    def test_aqua_parser_over_api_v2_empty(self):
        with (get_unit_tests_scans_path("aqua") / "over_api_v2_empty.json").open(encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_aqua_parser_api_v2_with_missing_fields(self):
        with (get_unit_tests_scans_path("aqua") / "api_v2_missing_fields.json").open(encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            # First result has null resource, second is missing cpe
            self.assertEqual(2, len(findings))
            self.assertEqual("CVE-2023-0001 - No resource name (No version) ", findings[0].title)
            self.assertEqual("CVE-2023-0002 - libcrypto (1.0.2) ", findings[1].title)

    def test_aqua_parser_api_v1_with_missing_fields(self):
        with (get_unit_tests_scans_path("aqua") / "api_v1_missing_fields.json").open(encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            # First cve is missing file, second has a null name
            self.assertEqual("CVE-2023-0003: None", findings[0].title)
            self.assertEqual(["CVE-2023-0003"], findings[0].unsaved_vulnerability_ids)
            self.assertEqual("None: /usr/lib/libssl.so", findings[1].title)
            self.assertIsNone(findings[1].unsaved_vulnerability_ids)

    def test_aqua_parser_cicd_with_missing_resource_fields(self):
        with (get_unit_tests_scans_path("aqua") / "cicd_missing_resource_fields.json").open(encoding="utf-8") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            # First node has a null resource, second resource is missing cpe and path
            self.assertEqual(2, len(findings))
            self.assertEqual("CVE-2023-0004 - No resource name (No version) ", findings[0].title)
            self.assertEqual("CVE-2023-0005 - busybox (1.30.1) ", findings[1].title)
