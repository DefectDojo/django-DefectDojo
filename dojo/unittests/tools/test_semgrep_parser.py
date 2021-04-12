from django.test import TestCase
from dojo.tools.semgrep.parser import SemgrepParser
from dojo.models import Test


class TestSemgrepParser(TestCase):

    def test_parse_empty(self):
        testfile = open("dojo/unittests/scans/semgrep/empty.json")
        parser = SemgrepParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        testfile = open("dojo/unittests/scans/semgrep/one_finding.json")
        parser = SemgrepParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Using CBC with PKCS5Padding is susceptible to padding orcale attacks", finding.title)
        self.assertEqual("Low", finding.severity)
        self.assertEqual("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02194.java", finding.file_path)
        self.assertEqual(64, finding.line)
        self.assertEqual("java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle", finding.vuln_id_from_tool)
        self.assertEqual(696, finding.cwe)
        self.assertEqual("javax crypto Cipher.getInstance(\"AES/GCM/NoPadding\");", finding.mitigation)

    def test_parse_many_finding(self):
        testfile = open("dojo/unittests/scans/semgrep/many_findings.json")
        parser = SemgrepParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(findings))
        finding = findings[0]
        self.assertEqual("Using CBC with PKCS5Padding is susceptible to padding orcale attacks", finding.title)
        self.assertEqual("Low", finding.severity)
        self.assertEqual("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02194.java", finding.file_path)
        self.assertEqual(64, finding.line)
        self.assertEqual("java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle", finding.vuln_id_from_tool)
        self.assertEqual(696, finding.cwe)
        self.assertEqual("javax crypto Cipher.getInstance(\"AES/GCM/NoPadding\");", finding.mitigation)
        finding = findings[2]
        self.assertEqual("Using CBC with PKCS5Padding is susceptible to padding orcale attacks", finding.title)
        self.assertEqual("Low", finding.severity)
        self.assertEqual("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01150.java", finding.file_path)
        self.assertEqual(66, finding.line)
        self.assertEqual("java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle", finding.vuln_id_from_tool)
        self.assertEqual(696, finding.cwe)
        self.assertEqual("javax crypto Cipher.getInstance(\"AES/GCM/NoPadding\");", finding.mitigation)

    def test_parse_repeated_finding(self):
        testfile = open("dojo/unittests/scans/semgrep/repeated_findings.json")
        parser = SemgrepParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Using CBC with PKCS5Padding is susceptible to padding orcale attacks", finding.title)
        self.assertEqual("Low", finding.severity)
        self.assertEqual("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01150.java", finding.file_path)
        self.assertEqual(66, finding.line)
        self.assertEqual("java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle", finding.vuln_id_from_tool)
        self.assertEqual(696, finding.cwe)
        self.assertEqual("javax crypto Cipher.getInstance(\"AES/GCM/NoPadding\");", finding.mitigation)
        self.assertEqual(2, finding.nb_occurences)
