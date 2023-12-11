from ..dojo_test_case import DojoTestCase
from dojo.models import Test, Engagement, Product
from dojo.tools.mobsf.parser import MobSFParser


class TestMobSFParser(DojoTestCase):

    def test_parse_file(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open("unittests/scans/mobsf/report1.json")
        parser = MobSFParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        self.assertEqual(22, len(findings))
        item = findings[0]
        self.assertEqual('android.permission.WRITE_EXTERNAL_STORAGE', item.title)
        self.assertEqual('High', item.severity)
        item = findings[2]
        self.assertEqual('android.permission.INTERNET', item.title)
        self.assertEqual('Info', item.severity)
        item = findings[10]
        self.assertEqual('This shared object does not have RELRO enabled', item.title)
        self.assertEqual('High', item.severity)
        self.assertEqual('lib/armeabi-v7a/libdivajni.so', item.file_path)
        self.assertEqual(7, item.nb_occurences)
        item = findings[17]
        self.assertEqual('Local File I/O Operations', item.title)
        self.assertEqual('Info', item.severity)
        self.assertEqual(1, item.nb_occurences)

    def test_parse_file2(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open("unittests/scans/mobsf/report2.json")
        parser = MobSFParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        self.assertEqual(0, len(findings))
        # TODO add more checks dedicated to this file

    def test_parse_file_3_1_9_android(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open("unittests/scans/mobsf/android.json")
        parser = MobSFParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        self.assertEqual(77, len(findings))
        # TODO add more checks dedicated to this file

    def test_parse_file_3_1_9_ios(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open("unittests/scans/mobsf/ios.json")
        parser = MobSFParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        self.assertEqual(11, len(findings))
        # TODO add more checks dedicated to this file

    def test_parse_file_mobsf_3_7_9(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open("unittests/scans/mobsf/mobsf_3_7_9.json")
        parser = MobSFParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        self.assertEqual(2, len(findings))
        self.assertEqual(findings[0].title, "The binary may contain the following insecure API(s) _memcpy\n, _strlen\n")
        self.assertEqual(findings[1].title, "The binary may use _malloc\n function instead of calloc")
        self.assertEqual(findings[0].severity, "High")
        self.assertEqual(findings[1].severity, "High")

    def test_parse_issue_9132(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open("unittests/scans/mobsf/issue_9132.json")
        parser = MobSFParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        self.assertEqual(37, len(findings))

    def test_parse_allsafe(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open("unittests/scans/mobsf/allsafe.json")
        parser = MobSFParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        self.assertEqual(55, len(findings))

    def test_parse_damnvulnrablebank(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open("unittests/scans/mobsf/damnvulnrablebank.json")
        parser = MobSFParser()
        findings = parser.get_findings(testfile, test)
        testfile.close()
        self.assertEqual(39, len(findings))
