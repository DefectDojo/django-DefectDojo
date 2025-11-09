from dojo.models import Test
from dojo.tools.deepfence_threatmapper.parser import DeepfenceThreatmapperParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDeepfenceThreatmapperParser(DojoTestCase):

    def test_parse_file_compliance_report(self):
        with (get_unit_tests_scans_path("deepfence_threatmapper") / "compliance_report.xlsx").open("rb") as testfile:
            parser = DeepfenceThreatmapperParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(7, len(findings))
            self.assertEqual(findings[0].title, "Threatmapper_Compliance_Report-gdpr_3.6")
            self.assertEqual(findings[0].severity, "Info")

    def test_parse_file_compliance_report_newformat(self):
        with (get_unit_tests_scans_path("deepfence_threatmapper") / "compliance_report_newformat.xlsx").open("rb") as testfile:
            parser = DeepfenceThreatmapperParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(66, len(findings))
            self.assertEqual(findings[0].title, "Threatmapper_Compliance_Report-gdpr_3.4")
            self.assertEqual(findings[0].severity, "Info")

    def test_parse_file_malware_report(self):
        with (get_unit_tests_scans_path("deepfence_threatmapper") / "malware_report.xlsx").open("rb") as testfile:
            parser = DeepfenceThreatmapperParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(9, len(findings))
            self.assertEqual(findings[0].title, "MD5_Constants")
            self.assertEqual(findings[0].severity, "Low")
            self.assertEqual(findings[0].file_path, "/tmp/Deepfence/YaraHunter/df_db09257b02e615049e0aecc05be2dc2401735e67db4ab74225df777c62c39753/usr/sbin/mkfs.cramfs")

    def test_parse_file_malware_report_newformat(self):
        with (get_unit_tests_scans_path("deepfence_threatmapper") / "malware_report_newformat.xlsx").open("rb") as testfile:
            parser = DeepfenceThreatmapperParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(66, len(findings))
            self.assertEqual(findings[0].title, "spyeye")
            self.assertEqual(findings[0].severity, "High")

    def test_parse_file_secret_report(self):
        with (get_unit_tests_scans_path("deepfence_threatmapper") / "secret_report.xlsx").open("rb") as testfile:
            parser = DeepfenceThreatmapperParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(7, len(findings))
            self.assertEqual(findings[0].title, "Username and password in URI")
            self.assertEqual(findings[0].severity, "High")
            self.assertEqual(findings[0].file_path, "usr/share/doc/curl-8.3.0/TheArtOfHttpScripting.md")

    def test_parse_file_secret_report_newformat(self):
        with (get_unit_tests_scans_path("deepfence_threatmapper") / "secret_report_newformat.xlsx").open("rb") as testfile:
            parser = DeepfenceThreatmapperParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(15, len(findings))
            self.assertEqual(findings[0].title, "index-username_and_password_in_uri in /var/lib/host-containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs/usr/lib64/python2.7/urllib2.py")
            self.assertEqual(findings[0].severity, "High")

    def test_parse_file_vulnerability_report(self):
        with (get_unit_tests_scans_path("deepfence_threatmapper") / "vulnerability_report.xlsx").open("rb") as testfile:
            parser = DeepfenceThreatmapperParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            self.assertEqual(findings[0].title, "Threatmapper_Vuln_Report-CVE-2021-36084")
            self.assertEqual(findings[0].severity, "Low")
            self.assertEqual(findings[0].mitigation, "2.5-10.amzn2.0.1")
            self.assertEqual(findings[0].cve, "CVE-2021-36084")

    def test_parse_file_vulnerability_report_newformat(self):
        with (get_unit_tests_scans_path("deepfence_threatmapper") / "vulnerability_report_newformat.xlsx").open("rb") as testfile:
            parser = DeepfenceThreatmapperParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(254, len(findings))
            self.assertEqual(findings[0].title, "Threatmapper_Vuln_Report-CVE-2005-2541")
            self.assertEqual(findings[0].severity, "Critical")
            self.assertEqual(findings[0].cve, "CVE-2005-2541")
