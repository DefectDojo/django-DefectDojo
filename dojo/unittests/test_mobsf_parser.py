from django.test import TestCase
from dojo.models import Test, Engagement, Product
from dojo.tools.mobsf.parser import MobSFParser


class TestMobSFParser(TestCase):
    # TODO fix this use case
    # def test_parse_without_file_has_no_findings(self):
    #     parser = MobSFParser(None, Test())
    #     self.assertEqual(0, len(parser.items))

    def test_parse_file(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open("dojo/unittests/scans/mobsf/report1.json")
        parser = MobSFParser(testfile, test)
        testfile.close()
        # TODO add more checks dedicated to this file
        # self.assertEqual(1, len(parser.items))
        # item = parser.items[0]
        # self.assertEquals('debian:stretch:libx11', item.component_name)
        # self.assertEquals('2:1.6.4-3', item.component_version)

    def test_parse_file2(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open("dojo/unittests/scans/mobsf/report2.json")
        parser = MobSFParser(testfile, test)
        testfile.close()
        # TODO add more checks dedicated to this file

    def test_parse_file_3_1_9_android(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open("dojo/unittests/scans/mobsf/android.json")
        parser = MobSFParser(testfile, test)
        testfile.close()
        # TODO add more checks dedicated to this file

    def test_parse_file_3_1_9_ios(self):
        test = Test()
        engagement = Engagement()
        engagement.product = Product()
        test.engagement = engagement
        testfile = open("dojo/unittests/scans/mobsf/ios.json")
        parser = MobSFParser(testfile, test)
        testfile.close()
        # TODO add more checks dedicated to this file
