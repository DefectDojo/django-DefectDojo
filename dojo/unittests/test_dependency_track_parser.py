from django.test import TestCase
from dojo.tools.dependency_track.parser import DependencyTrackParser
from dojo.models import Test


class TestDependencyTrackParser(TestCase):
    def test_dependency_track_parser_without_file_has_no_findings(self):
        parser = DependencyTrackParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_dependency_track_parser_with_empty_list_for_findings_key_has_no_findings(self):
        testfile = open("dojo/unittests/scans/dependency_track_samples/no_findings_because_findings_key_is_empty_list.json")
        parser = DependencyTrackParser(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(parser.items))

    def test_dependency_track_parser_with_missing_findings_key_has_no_findings(self):
        testfile = open("dojo/unittests/scans/dependency_track_samples/no_findings_because_findings_key_is_missing.json")
        parser = DependencyTrackParser(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(parser.items))

    def test_dependency_track_parser_with_null_findings_key_has_no_findings(self):
        testfile = open("dojo/unittests/scans/dependency_track_samples/no_findings_because_findings_key_is_null.json")
        parser = DependencyTrackParser(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(parser.items))

    def test_dependency_track_parser_has_many_findings(self):
        testfile = open("dojo/unittests/scans/dependency_track_samples/many_findings.json")
        parser = DependencyTrackParser(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(parser.items))

    def test_dependency_track_parser_has_one_finding(self):
        testfile = open("dojo/unittests/scans/dependency_track_samples/one_finding.json")
        parser = DependencyTrackParser(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(parser.items))
