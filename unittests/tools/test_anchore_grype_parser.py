from dojo.models import Finding, Test
from dojo.tools.anchore_grype.parser import AnchoreGrypeParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAnchoreGrypeParser(DojoTestCase):

    def test_parser_has_no_findings(self):
        with (get_unit_tests_scans_path("anchore_grype") / "no_vuln.json").open(encoding="utf-8") as testfile:
            parser = AnchoreGrypeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parser_has_many_findings(self):
        found = False
        with (get_unit_tests_scans_path("anchore_grype") / "many_vulns.json").open(encoding="utf-8") as testfile:
            parser = AnchoreGrypeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1509, len(findings))
            for finding in findings:
                self.assertIn(finding.severity, Finding.SEVERITIES)
                vulnerability_ids = finding.unsaved_vulnerability_ids
                self.assertGreaterEqual(len(vulnerability_ids), 1)
                if finding.vuln_id_from_tool == "CVE-2011-3389":
                    vulnerability_ids = finding.unsaved_vulnerability_ids
                    self.assertEqual(1, len(vulnerability_ids))
                    self.assertEqual("CVE-2011-3389", vulnerability_ids[0])
                    self.assertEqual("Medium", finding.severity)
                    self.assertEqual("libgnutls-openssl27", finding.component_name)
                    self.assertEqual("3.6.7-4+deb10u5", finding.component_version)
                    self.assertEqual("/var/lib/dpkg/status", finding.file_path)
                    found = True
                    break
            self.assertTrue(found)

    def test_grype_parser_with_one_critical_vuln_has_one_findings(self):
        found = False
        with (get_unit_tests_scans_path("anchore_grype") / "many_vulns2.json").open(encoding="utf-8") as testfile:
            parser = AnchoreGrypeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1567, len(findings))
            for finding in findings:
                self.assertIn(finding.severity, Finding.SEVERITIES)
                vulnerability_ids = finding.unsaved_vulnerability_ids
                self.assertGreaterEqual(len(vulnerability_ids), 1)
                if finding.vuln_id_from_tool == "CVE-2019-9192":
                    vulnerability_ids = finding.unsaved_vulnerability_ids
                    self.assertEqual(1, len(vulnerability_ids))
                    self.assertEqual("CVE-2019-9192", vulnerability_ids[0])
                    self.assertEqual("libc6-dev", finding.component_name)
                    self.assertEqual("2.28-10", finding.component_version)
                    self.assertEqual("Info", finding.severity)
                    found = True
                    break
            self.assertTrue(found)

    def test_grype_parser_with_many_vulns3(self):
        found = False
        with (get_unit_tests_scans_path("anchore_grype") / "many_vulns3.json").open(encoding="utf-8") as testfile:
            parser = AnchoreGrypeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(327, len(findings))
            for finding in findings:
                self.assertIn(finding.severity, Finding.SEVERITIES)
                vulnerability_ids = finding.unsaved_vulnerability_ids
                self.assertGreaterEqual(len(vulnerability_ids), 1)
                if finding.vuln_id_from_tool == "CVE-2011-3389":
                    vulnerability_ids = finding.unsaved_vulnerability_ids
                    self.assertEqual(1, len(vulnerability_ids))
                    self.assertEqual("CVE-2011-3389", vulnerability_ids[0])
                    self.assertEqual("Medium", finding.severity)
                    self.assertEqual("libgnutls30", finding.component_name)
                    self.assertEqual("3.6.7-4+deb10u5", finding.component_version)
                    found = True
                    break
            self.assertTrue(found)

    def test_grype_parser_with_new_matcher_list(self):
        found = False
        with (get_unit_tests_scans_path("anchore_grype") / "many_vulns4.json").open(encoding="utf-8") as testfile:
            parser = AnchoreGrypeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(9, len(findings))
            for finding in findings:
                self.assertIn(finding.severity, Finding.SEVERITIES)
                vulnerability_ids = finding.unsaved_vulnerability_ids
                self.assertGreaterEqual(len(vulnerability_ids), 1)
                if finding.vuln_id_from_tool == "CVE-1999-1338":
                    vulnerability_ids = finding.unsaved_vulnerability_ids
                    self.assertEqual(1, len(vulnerability_ids))
                    self.assertEqual("CVE-1999-1338", vulnerability_ids[0])
                    self.assertEqual("Medium", finding.severity)
                    self.assertIn("javascript-matcher", finding.description)
                    self.assertEqual("delegate", finding.component_name)
                    self.assertEqual("3.2.0", finding.component_version)
                    found = True
            self.assertTrue(found)

    def test_check_all_fields(self):
        with (get_unit_tests_scans_path("anchore_grype") / "check_all_fields.json").open(encoding="utf-8") as testfile:
            parser = AnchoreGrypeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(5, len(findings))

            finding = findings[0]
            self.assertEqual("CVE-2004-0971 in libgssapi-krb5-2:1.17-3+deb10u3", finding.title)
            description = """**Vulnerability Namespace:** debian:10
**Related Vulnerability Description:** The krb5-send-pr script in the kerberos5 (krb5) package in Trustix Secure Linux 1.5 through 2.1, and possibly other operating systems, allows local users to overwrite files via a symlink attack on temporary files.
**Matcher:** dpkg-matcher
**Package URL:** pkg:deb/debian/libgssapi-krb5-2@1.17-3+deb10u3?arch=amd64"""
            self.assertEqual(description, finding.description)
            vulnerability_ids = finding.unsaved_vulnerability_ids
            self.assertEqual(2, len(vulnerability_ids))
            self.assertEqual("CVE-2004-0971", vulnerability_ids[0])
            self.assertEqual("CVE-2004-0971", vulnerability_ids[1])
            self.assertIsNone(finding.cvssv3)
            self.assertIsNone(finding.cvssv3_score)
            self.assertEqual("Info", finding.severity)
            self.assertIsNone(finding.mitigation)
            references = """**Vulnerability Datasource:** https://security-tracker.debian.org/tracker/CVE-2004-0971
**Related Vulnerability Datasource:** https://nvd.nist.gov/vuln/detail/CVE-2004-0971
**Related Vulnerability URLs:**
- http://www.securityfocus.com/bid/11289
- http://www.gentoo.org/security/en/glsa/glsa-200410-24.xml
- http://www.redhat.com/support/errata/RHSA-2005-012.html
- http://www.trustix.org/errata/2004/0050
- http://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=136304
- https://exchange.xforce.ibmcloud.com/vulnerabilities/17583
- https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A10497
- https://lists.apache.org/thread.html/rc713534b10f9daeee2e0990239fa407e2118e4aa9e88a7041177497c@%3Cissues.guacamole.apache.org%3E"""
            self.assertEqual(references, finding.references)
            self.assertEqual("libgssapi-krb5-2", finding.component_name)
            self.assertEqual("1.17-3+deb10u3", finding.component_version)
            self.assertEqual("CVE-2004-0971", finding.vuln_id_from_tool)
            self.assertEqual(["dpkg"], finding.tags)
            self.assertEqual(1, finding.nb_occurences)

            finding = findings[1]
            self.assertEqual("CVE-2021-32626 in redis:4.0.2", finding.title)
            description = """**Vulnerability Namespace:** nvd
**Vulnerability Description:** Redis is an open source, in-memory database that persists on disk. In affected versions specially crafted Lua scripts executing in Redis can cause the heap-based Lua stack to be overflowed, due to incomplete checks for this condition. This can result with heap corruption and potentially remote code execution. This problem exists in all versions of Redis with Lua scripting support, starting from 2.6. The problem is fixed in versions 6.2.6, 6.0.16 and 5.0.14. For users unable to update an additional workaround to mitigate the problem without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.
**Matchers:**
- python-matcher
- python2-matcher
**Package URL:** pkg:pypi/redis@4.0.2"""
            self.assertEqual(description, finding.description)
            vulnerability_ids = finding.unsaved_vulnerability_ids
            self.assertEqual(1, len(vulnerability_ids))
            self.assertEqual("CVE-2021-32626", vulnerability_ids[0])
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
            self.assertEqual("High", finding.severity)
            mitigation = """Upgrade to version:
- fix_1
- fix_2"""
            self.assertEqual(mitigation, finding.mitigation)
            references = """**Vulnerability Datasource:** https://nvd.nist.gov/vuln/detail/CVE-2021-32626
**Vulnerability URLs:**
- https://github.com/redis/redis/commit/666ed7facf4524bf6d19b11b20faa2cf93fdf591
- https://github.com/redis/redis/security/advisories/GHSA-p486-xggp-782c
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VL5KXFN3ATM7IIM7Q4O4PWTSRGZ5744Z/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HTYQ5ZF37HNGTZWVNJD3VXP7I6MEEF42/
- https://lists.apache.org/thread.html/r75490c61c2cb7b6ae2c81238fd52ae13636c60435abcd732d41531a0@%3Ccommits.druid.apache.org%3E
- https://security.netapp.com/advisory/ntap-20211104-0003/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WR5WKJWXD4D6S3DJCZ56V74ESLTDQRAB/
- https://www.debian.org/security/2021/dsa-5001"""
            self.assertEqual(references, finding.references)
            self.assertEqual("redis", finding.component_name)
            self.assertEqual("4.0.2", finding.component_version)
            self.assertEqual("CVE-2021-32626", finding.vuln_id_from_tool)
            self.assertEqual(["python", "python2"], finding.tags)
            self.assertEqual(1, finding.nb_occurences)

            finding = findings[2]
            self.assertEqual("CVE-2021-33574 in libc-bin:2.28-10", finding.title)
            description = """**Vulnerability Namespace:** debian:10
**Related Vulnerability Description:** The mq_notify function in the GNU C Library (aka glibc) versions 2.32 and 2.33 has a use-after-free. It may use the notification thread attributes object (passed through its struct sigevent parameter) after it has been freed by the caller, leading to a denial of service (application crash) or possibly unspecified other impact.
**Matcher:** dpkg-matcher
**Package URL:** pkg:deb/debian/libc-bin@2.28-10?arch=amd64"""
            self.assertEqual(description, finding.description)
            vulnerability_ids = finding.unsaved_vulnerability_ids
            self.assertEqual(2, len(vulnerability_ids))
            self.assertEqual("CVE-2021-33574", vulnerability_ids[0])
            self.assertEqual("CVE-2021-33574", vulnerability_ids[1])
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
            self.assertEqual("Critical", finding.severity)
            self.assertIsNone(finding.mitigation)
            references = """**Vulnerability Datasource:** https://security-tracker.debian.org/tracker/CVE-2021-33574
**Related Vulnerability Datasource:** https://nvd.nist.gov/vuln/detail/CVE-2021-33574
**Related Vulnerability URLs:**
- https://sourceware.org/bugzilla/show_bug.cgi?id=27896
- https://sourceware.org/bugzilla/show_bug.cgi?id=27896#c1
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/
- https://security.netapp.com/advisory/ntap-20210629-0005/
- https://security.gentoo.org/glsa/202107-07
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/"""
            self.assertEqual(references, finding.references)
            self.assertEqual("libc-bin", finding.component_name)
            self.assertEqual("2.28-10", finding.component_version)
            self.assertEqual("CVE-2021-33574", finding.vuln_id_from_tool)
            self.assertEqual(["dpkg"], finding.tags)
            self.assertEqual(1, finding.nb_occurences)

            finding = findings[3]
            self.assertEqual("CVE-2021-33574 in libc6:2.28-10", finding.title)
            description = """**Vulnerability Namespace:** debian:10
**Related Vulnerability Description:** The mq_notify function in the GNU C Library (aka glibc) versions 2.32 and 2.33 has a use-after-free. It may use the notification thread attributes object (passed through its struct sigevent parameter) after it has been freed by the caller, leading to a denial of service (application crash) or possibly unspecified other impact.
**Matcher:** dpkg-matcher
**Package URL:** pkg:deb/debian/libc6@2.28-10?arch=amd64"""
            self.assertEqual(description, finding.description)
            vulnerability_ids = finding.unsaved_vulnerability_ids
            self.assertEqual(2, len(vulnerability_ids))
            self.assertEqual("CVE-2021-33574", vulnerability_ids[0])
            self.assertEqual("CVE-2021-33574", vulnerability_ids[1])
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
            self.assertEqual("Critical", finding.severity)
            self.assertIsNone(finding.mitigation)
            references = """**Vulnerability Datasource:** https://security-tracker.debian.org/tracker/CVE-2021-33574
**Related Vulnerability Datasource:** https://nvd.nist.gov/vuln/detail/CVE-2021-33574
**Related Vulnerability URLs:**
- https://sourceware.org/bugzilla/show_bug.cgi?id=27896
- https://sourceware.org/bugzilla/show_bug.cgi?id=27896#c1
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RBUUWUGXVILQXVWEOU7N42ICHPJNAEUP/
- https://security.netapp.com/advisory/ntap-20210629-0005/
- https://security.gentoo.org/glsa/202107-07
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KJYYIMDDYOHTP2PORLABTOHYQYYREZDD/"""
            self.assertEqual(references, finding.references)
            self.assertEqual("libc6", finding.component_name)
            self.assertEqual("2.28-10", finding.component_version)
            self.assertEqual("CVE-2021-33574", finding.vuln_id_from_tool)
            self.assertEqual(["dpkg"], finding.tags)
            self.assertEqual(1, finding.nb_occurences)

            finding = findings[4]
            self.assertEqual("GHSA-v6rh-hp5x-86rv in Django:3.2.9", finding.title)
            description = """**Vulnerability Namespace:** github:python
**Vulnerability Description:** Potential bypass of an upstream access control based on URL paths in Django
**Related Vulnerability Description:** In Django 2.2 before 2.2.25, 3.1 before 3.1.14, and 3.2 before 3.2.10, HTTP requests for URLs with trailing newlines could bypass upstream access control based on URL paths.
**Matcher:** python-matcher
**Package URL:** pkg:pypi/Django@3.2.9"""
            self.assertEqual(description, finding.description)
            vulnerability_ids = finding.unsaved_vulnerability_ids
            self.assertEqual(2, len(vulnerability_ids))
            self.assertEqual("GHSA-v6rh-hp5x-86rv", vulnerability_ids[0])
            self.assertEqual("CVE-2021-44420", vulnerability_ids[1])
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", finding.cvssv3)
            self.assertEqual("High", finding.severity)
            mitigation = "Upgrade to version: 3.2.10"
            self.assertEqual(mitigation, finding.mitigation)
            references = """**Vulnerability Datasource:** https://github.com/advisories/GHSA-v6rh-hp5x-86rv
**Related Vulnerability Datasource:** https://nvd.nist.gov/vuln/detail/CVE-2021-44420
**Related Vulnerability URLs:**
- https://docs.djangoproject.com/en/3.2/releases/security/
- https://www.openwall.com/lists/oss-security/2021/12/07/1
- https://www.djangoproject.com/weblog/2021/dec/07/security-releases/
- https://groups.google.com/forum/#!forum/django-announce"""
            self.assertEqual(references, finding.references)
            self.assertEqual("Django", finding.component_name)
            self.assertEqual("3.2.9", finding.component_version)
            self.assertEqual("GHSA-v6rh-hp5x-86rv", finding.vuln_id_from_tool)
            self.assertEqual(["python"], finding.tags)
            self.assertEqual(2, finding.nb_occurences)

    def test_grype_issue_9618(self):
        with (get_unit_tests_scans_path("anchore_grype") / "issue_9618.json").open(encoding="utf-8") as testfile:
            parser = AnchoreGrypeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(35, len(findings))

    def test_grype_fix_not_available(self):
        with (get_unit_tests_scans_path("anchore_grype") / "fix_not_available.json").open(encoding="utf-8") as testfile:
            parser = AnchoreGrypeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            self.assertEqual(findings[0].fix_available, False)
            self.assertEqual(findings[0].fix_version, None)

    def test_grype_fix_available(self):
        with (get_unit_tests_scans_path("anchore_grype") / "fix_available.json").open(encoding="utf-8") as testfile:
            parser = AnchoreGrypeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            self.assertEqual(findings[0].fix_available, True)
            self.assertEqual(findings[0].fix_version, "1.2.3")

    def test_grype_issue_9942(self):
        with (get_unit_tests_scans_path("anchore_grype") / "issue_9942.json").open(encoding="utf-8") as testfile:
            parser = AnchoreGrypeParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_grype_epss_values(self):
        with (get_unit_tests_scans_path("anchore_grype") / "many_vulns_with_epss_values.json").open(encoding="utf-8") as testfile:
            parser = AnchoreGrypeParser()
            findings = parser.get_findings(testfile, Test())

            # Hardcoded expected values
            expected = [
                ("CVE-2022-28391", 0.0719, 0.91123),
                ("CVE-2021-28831", 0.00878, 0.74313),
                ("CVE-2022-48174", 0.00451, 0.62761),
                ("CVE-2021-42380", 0.00277, 0.50908),
                ("CVE-2021-42381", 0.00197, 0.42221),
                ("CVE-2021-42382", 0.00197, 0.42221),
                ("CVE-2021-42386", 0.00183, 0.40722),
                ("CVE-2021-42385", 0.0018, 0.40314),
                ("CVE-2021-42378", 0.00145, 0.35906),
                ("CVE-2021-42379", 0.00145, 0.35906),
                ("CVE-2021-42384", 0.00145, 0.35906),
                ("CVE-2021-42374", 0.00077, 0.23977),
                ("CVE-2021-42376", 0.00028, 0.06078),
                ("CVE-2024-58251", 0.0002, 0.0361),
                ("CVE-2025-46394", 0.00017, 0.02652),
            ]
            self.assertEqual(len(expected), len(findings))

            for (cve, epss_score, epss_percentile), finding in zip(expected, findings, strict=True):
                self.assertEqual(cve, finding.vuln_id_from_tool)
                self.assertIsNotNone(finding.epss_score)
                self.assertAlmostEqual(epss_score, finding.epss_score, places=5)
                self.assertIsNotNone(finding.epss_percentile)
                self.assertAlmostEqual(epss_percentile, finding.epss_percentile, places=5)

    def test_grype_epss_problem(self):
        """
        This test is to check that the parser is able to handle the case where the epss score is not found in the vulnerability itself
        and must be found in the (first) related vulnerability.
        """
        with (get_unit_tests_scans_path("anchore_grype") / "anchore_grype_epss_problem.json").open(encoding="utf-8") as testfile:
            parser = AnchoreGrypeParser()
            findings = parser.get_findings(testfile, Test())

            # Hardcoded expected values
            expected = [
                ("GHSA-4374-p667-p6c8", 0.00163, 0.37957),
            ]
            self.assertEqual(len(expected), len(findings))

            for (cve, epss_score, epss_percentile), finding in zip(expected, findings, strict=True):
                self.assertEqual(cve, finding.vuln_id_from_tool)
                self.assertIsNotNone(finding.epss_score)
                self.assertAlmostEqual(epss_score, finding.epss_score, places=5)
                self.assertIsNotNone(finding.epss_percentile)
                self.assertAlmostEqual(epss_percentile, finding.epss_percentile, places=5)
