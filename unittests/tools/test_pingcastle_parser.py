from dojo.tools.pingcastle.parser import PingCastleParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestPingCastleParser(DojoTestCase):

    def test_no_findings(self):
        with (get_unit_tests_scans_path("pingcastle") / "zero.xml").open(encoding="utf-8") as my_file_handle:
            parser = PingCastleParser()
            findings = parser.get_findings(my_file_handle, None)
        self.assertEqual(0, len(findings))

    def test_one_finding(self):
        with (get_unit_tests_scans_path("pingcastle") / "one.xml").open(encoding="utf-8") as my_file_handle:
            parser = PingCastleParser()
            findings = parser.get_findings(my_file_handle, None)
        self.assertEqual(1, len(findings))
        self.validate_locations(findings)
        self.assertTrue(self.get_unsaved_locations(findings[0]))
        self.assertEqual(findings[0].title, "[PingCastle] A-MinPwdLen (Anomalies/WeakPassword)")
        self.assertEqual(findings[0].severity, "Medium")

    def test_many_findings(self):
        with (get_unit_tests_scans_path("pingcastle") / "many.xml").open(encoding="utf-8") as my_file_handle:
            parser = PingCastleParser()
            findings = parser.get_findings(my_file_handle, None)
        self.assertEqual(28, len(findings))
        self.validate_locations(findings)
        admin_login = next((f for f in findings if f.vuln_id_from_tool == "P-AdminLogin"), None)
        self.assertIsNotNone(admin_login)
        self.assertEqual(admin_login.title, "[PingCastle] P-AdminLogin (PrivilegedAccounts/AdminControl)")
        self.assertEqual(admin_login.severity, "Critical")
        spooler = next((f for f in findings if f.vuln_id_from_tool == "A-DC-Spooler"), None)
        self.assertIsNotNone(spooler)
        self.assertEqual(spooler.title, "[PingCastle] A-DC-Spooler (Anomalies/PassTheCredential)")
        self.assertEqual(spooler.severity, "High")
        self.assertTrue(self.get_unsaved_locations(spooler))
        ds_heuristics = next((f for f in findings if f.vuln_id_from_tool == "A-DsHeuristicsLDAPSecurity"), None)
        self.assertIsNotNone(ds_heuristics)
        self.assertEqual(ds_heuristics.title, "[PingCastle] A-DsHeuristicsLDAPSecurity (Anomalies/Reconnaissance)")
        self.assertEqual(ds_heuristics.severity, "Medium")
        self.assertTrue(
            hasattr(ds_heuristics, "unsaved_vulnerability_ids")
            and len(ds_heuristics.unsaved_vulnerability_ids) >= 1,
        )
        coerce = next((f for f in findings if f.vuln_id_from_tool == "A-DC-Coerce"), None)
        self.assertIsNotNone(coerce)
        self.assertEqual(coerce.severity, "High")
