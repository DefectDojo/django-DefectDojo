from dojo.models import Test
from dojo.tools.fortify.parser import FortifyParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestFortifyParser(DojoTestCase):
    def test_fortify_many_findings(self):
        with open(get_unit_tests_scans_path("fortify") / "fortify_many_findings.xml", encoding="utf-8") as testfile:
            parser = FortifyParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(324, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Poor Logging Practice: Use of a System Output Stream - XXE.java: 81", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertEqual("src/main/java/org/joychou/controller/XXE.java", finding.file_path)
                self.assertEqual(81, finding.line)

    def test_fortify_few_findings(self):
        with open(get_unit_tests_scans_path("fortify") / "fortify_few_findings.xml", encoding="utf-8") as testfile:
            parser = FortifyParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Privilege Management: Unnecessary Permission - AndroidManifest.xml: 11", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual("app/build/intermediates/bundle_manifest/developDebug/processDevelopDebugManifest/bundle-manifest/AndroidManifest.xml", finding.file_path)
            with self.subTest(i=1):
                self.assertEqual(11, finding.line)
                self.assertEqual("53C25D2FC6950554F16D3CEF9E41EF6F", finding.unique_id_from_tool)

    def test_fortify_few_findings_count_chart(self):
        with open(get_unit_tests_scans_path("fortify") / "fortify_few_findings_count_chart.xml", encoding="utf-8") as testfile:
            parser = FortifyParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Privilege Management: Unnecessary Permission - AndroidManifest.xml: 11", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual("app/build/intermediates/bundle_manifest/developDebug/processDevelopDebugManifest/bundle-manifest/AndroidManifest.xml", finding.file_path)
                self.assertEqual(11, finding.line)
                self.assertEqual("53C25D2FC6950554F16D3CEF9E41EF6F", finding.unique_id_from_tool)

    def test_fortify_issue6260(self):
        with open(get_unit_tests_scans_path("fortify") / "issue6260.xml", encoding="utf-8") as testfile:
            parser = FortifyParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(16, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Command Injection - command.java: 40", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertEqual("src/main/java/command.java", finding.file_path)
                self.assertEqual(40, finding.line)
                self.assertEqual("7A2F1C728BDDBB17C7CB31CEDF5D8F85", finding.unique_id_from_tool)

    def test_fortify_issue6082(self):
        with open(get_unit_tests_scans_path("fortify") / "issue6082.xml", encoding="utf-8") as testfile:
            parser = FortifyParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Privacy Violation: Autocomplete - login.html: 19", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual("login.html", finding.file_path)
                self.assertEqual(19, finding.line)
                self.assertEqual("F46C9EF7203D77D83D3486BCDC78565F", finding.unique_id_from_tool)
            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Unreleased Resource: Database - MyContextListener.java: 28", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual("src/adrui/MyContextListener.java", finding.file_path)
                self.assertEqual(28, finding.line)
                self.assertEqual("B5B15F27E10F4D7799BD0ED1E6D34C5D", finding.unique_id_from_tool)

    def test_fortify_many_fdr_findings(self):
        with open(get_unit_tests_scans_path("fortify") / "many_findings.fpr", encoding="utf-8") as testfile:
            parser = FortifyParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(61, len(findings))
            # for i in range(len(findings)):
            #     print(f"{i}: {findings[i]}: {findings[i].severity}")

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Cross-Site Request Forgery - category.html: 219 (114E5A67-3446-4DD5-B578-D0E6FDBB304E)", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertEqual("1B87289954501EF8FD3861819DD98C27", finding.unique_id_from_tool)
                self.assertEqual("public/category.html", finding.file_path)
                self.assertEqual(219, finding.line)
            with self.subTest(i=1):
                finding = findings[50]
                self.assertEqual("Insecure Transport - footer.html: 104 (C72A3E77-8324-4FF9-B958-74FCDDF39D17)", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("D739B2E51B127BDFA4FE07B5A7662A45", finding.unique_id_from_tool)
                self.assertEqual("public/footer.html", finding.file_path)
                self.assertEqual(104, finding.line)

    def test_fortify_hello_world_fdr_findings(self):
        with open(get_unit_tests_scans_path("fortify") / "hello_world.fpr", encoding="utf-8") as testfile:
            parser = FortifyParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))
            # for i in range(len(findings)):
            #     print(f"{i}: {findings[i]}: {findings[i].severity}")

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Password Management - HelloWorld.java: 5 (720E3A66-55AC-4D2D-8DB9-DC30E120A52F)", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertEqual("A5338E223E737FF81F8A806C50A05969", finding.unique_id_from_tool)
                self.assertEqual("src/main/java/hello/HelloWorld.java", finding.file_path)
                self.assertEqual(5, finding.line)
            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Password Management - HelloWorld.java: 13 (9C5BD1B5-C296-48d4-B5F5-5D2958661BC4)", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual("D3166922519EDD92D132761602EB71B4", finding.unique_id_from_tool)
                self.assertEqual("src/main/java/hello/HelloWorld.java", finding.file_path)
                self.assertEqual(13, finding.line)

    def test_fortify_issue_12065(self):
        with open(get_unit_tests_scans_path("fortify") / "issue_12065.xml", encoding="utf-8") as testfile:
            parser = FortifyParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(15, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Cookie Security: Cookie not Sent Over SSL", finding.title)
                self.assertEqual("Medium", finding.severity)
