from django.test import TestCase
from dojo.tools.njsscan.parser import NjsscanParser
from dojo.models import Test


class TestNjsscanParser(TestCase):

    def test_parse_no_findings(self):
        testfile = open("dojo/unittests/scans/njsscan/no_findings.json")
        parser = NjsscanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_many_nodejs_findings(self):
        testfile = open("dojo/unittests/scans/njsscan/many_nodejs_findings.json")
        parser = NjsscanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(14, len(findings))

        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("express_xss", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(79, finding.cwe)
            self.assertEqual("/app/jwt_hardcoded.js", finding.file_path)
            self.assertEqual(83, finding.line)

        with self.subTest(i=1):
            finding = findings[1]
            self.assertEqual("hardcoded_jwt_secret", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(798, finding.cwe)
            self.assertEqual("/app/jwt_hardcoded.js", finding.file_path)
            self.assertEqual(2, finding.line)

        with self.subTest(i=2):
            finding = findings[2]
            self.assertEqual("hardcoded_jwt_secret", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(798, finding.cwe)
            self.assertEqual("/app/jwt_hardcoded.js", finding.file_path)
            self.assertEqual(99, finding.line)

        with self.subTest(i=3):
            finding = findings[3]
            self.assertEqual("jwt_exposed_credentials", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(522, finding.cwe)
            self.assertEqual("/app/jwt_exposed_credentials.js", finding.file_path)
            self.assertEqual(4, finding.line)

        with self.subTest(i=4):
            finding = findings[4]
            self.assertEqual("jwt_exposed_credentials", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(522, finding.cwe)
            self.assertEqual("/app/jwt_exposed_credentials.js", finding.file_path)
            self.assertEqual(111, finding.line)

        with self.subTest(i=5):
            finding = findings[5]
            self.assertEqual("jwt_exposed_data", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(522, finding.cwe)
            self.assertEqual("/app/jwt_exposed_data.js", finding.file_path)
            self.assertEqual(6, finding.line)

        with self.subTest(i=6):
            finding = findings[6]
            self.assertEqual("jwt_exposed_data", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(522, finding.cwe)
            self.assertEqual("/app/jwt_hardcoded.js", finding.file_path)
            self.assertEqual(42, finding.line)

        with self.subTest(i=7):
            finding = findings[7]
            self.assertEqual("jwt_express_hardcoded", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(522, finding.cwe)
            self.assertEqual("/app/jwt_express_hardcoded.js", finding.file_path)
            self.assertEqual(4, finding.line)

        with self.subTest(i=8):
            finding = findings[8]
            self.assertEqual("jwt_express_hardcoded", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(522, finding.cwe)
            self.assertEqual("/app/jwt_express_hardcoded.js", finding.file_path)
            self.assertEqual(21, finding.line)

        with self.subTest(i=9):
            finding = findings[9]
            self.assertEqual("jwt_not_revoked", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(522, finding.cwe)
            self.assertEqual("/app/jwt_express_hardcoded.js", finding.file_path)
            self.assertEqual(13, finding.line)

        with self.subTest(i=10):
            finding = findings[10]
            self.assertEqual("node_jwt_none_algorithm", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(327, finding.cwe)
            self.assertEqual("/app/jwt_none_algorithm.js", finding.file_path)
            self.assertEqual(2, finding.line)

        with self.subTest(i=11):
            finding = findings[11]
            self.assertEqual("node_jwt_none_algorithm", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(327, finding.cwe)
            self.assertEqual("/app/jwt_none_algorithm.js", finding.file_path)
            self.assertEqual(8, finding.line)

        with self.subTest(i=12):
            finding = findings[12]
            self.assertEqual("node_secret", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(798, finding.cwe)
            self.assertEqual("/app/jwt_none_algorithm.js", finding.file_path)
            self.assertEqual(9, finding.line)

        with self.subTest(i=13):
            finding = findings[13]
            self.assertEqual("node_secret", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(798, finding.cwe)
            self.assertEqual("/app/jwt_hardcoded.js", finding.file_path)
            self.assertEqual(8, finding.line)

    def test_parse_many_template_findings(self):
        testfile = open("dojo/unittests/scans/njsscan/many_template_findings.json")
        parser = NjsscanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(14, len(findings))

        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("dust_template", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(79, finding.cwe)
            self.assertEqual("/app/dust.tl", finding.file_path)
            self.assertEqual(1, finding.line)

        with self.subTest(i=1):
            finding = findings[1]
            self.assertEqual("ejs_ect_template", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(79, finding.cwe)
            self.assertEqual("/app/ejs_template.ejs", finding.file_path)
            self.assertEqual(1, finding.line)

        with self.subTest(i=2):
            finding = findings[2]
            self.assertEqual("ejs_ect_template", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(79, finding.cwe)
            self.assertEqual("/app/ect.tmpl", finding.file_path)
            self.assertEqual(5, finding.line)

        with self.subTest(i=3):
            finding = findings[3]
            self.assertEqual("electronjs_disable_websecurity", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(79, finding.cwe)
            self.assertEqual("/app/electron.html", finding.file_path)
            self.assertEqual(6, finding.line)

        with self.subTest(i=4):
            finding = findings[4]
            self.assertEqual("electronjs_node_integration", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(272, finding.cwe)
            self.assertEqual("/app/electron.html", finding.file_path)
            self.assertEqual(4, finding.line)

        with self.subTest(i=5):
            finding = findings[5]
            self.assertEqual("electronjs_node_integration", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(272, finding.cwe)
            self.assertEqual("/app/electron.html", finding.file_path)
            self.assertEqual(1, finding.line)

        with self.subTest(i=6):
            finding = findings[6]
            self.assertEqual("handlebar_mustache_template", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(79, finding.cwe)
            self.assertEqual("/app/mustache.mustache", finding.file_path)
            self.assertEqual(7, finding.line)

        with self.subTest(i=7):
            finding = findings[7]
            self.assertEqual("handlebar_mustache_template", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(79, finding.cwe)
            self.assertEqual("/app/handlebars.hbs", finding.file_path)
            self.assertEqual(1, finding.line)

        with self.subTest(i=8):
            finding = findings[8]
            self.assertEqual("pug_jade_template", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(79, finding.cwe)
            self.assertEqual("/app/jade_template.jade", finding.file_path)
            self.assertEqual(3, finding.line)

        with self.subTest(i=9):
            finding = findings[9]
            self.assertEqual("pug_jade_template", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(79, finding.cwe)
            self.assertEqual("/app/pug.pug", finding.file_path)
            self.assertEqual(1, finding.line)

        with self.subTest(i=10):
            finding = findings[10]
            self.assertEqual("squirrelly_template", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(79, finding.cwe)
            self.assertEqual("/app/squirrelly.js.html", finding.file_path)
            self.assertEqual(1, finding.line)

        with self.subTest(i=11):
            finding = findings[11]
            self.assertEqual("squirrelly_template", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(79, finding.cwe)
            self.assertEqual("/app/squirrelly.js.html", finding.file_path)
            self.assertEqual(2, finding.line)

        with self.subTest(i=12):
            finding = findings[12]
            self.assertEqual("underscore_template", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(79, finding.cwe)
            self.assertEqual("/app/underscore.html", finding.file_path)
            self.assertEqual(8, finding.line)

        with self.subTest(i=13):
            finding = findings[13]
            self.assertEqual("vue_template", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(79, finding.cwe)
            self.assertEqual("/app/vue.vue", finding.file_path)
            self.assertEqual(8, finding.line)
