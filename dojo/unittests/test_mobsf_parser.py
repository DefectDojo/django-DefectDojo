from django.test import TestCase
from dojo.models import Test
from dojo.tools.mobsf.parser import MobSFParser


class TestMobSFParser(TestCase):
    def test_parse_file(self):
        testfile = open("dojo/unittests/scans/mobsf/report1.json")
        parser = MobSFParser(testfile, Test())
        testfile.close()
        # TODO add more checks dedicated to this file
        # self.assertEqual(1, len(parser.items))
        # item = parser.items[0]
        # self.assertEquals('debian:stretch:libx11', item.component_name)
        # self.assertEquals('2:1.6.4-3', item.component_version)

    def test_parse_file2(self):
        testfile = open("dojo/unittests/scans/mobsf/report2.json")
        parser = MobSFParser(testfile, Test())
        testfile.close()
        # TODO add more checks dedicated to this file
