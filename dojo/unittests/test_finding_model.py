from django.test import TestCase
from dojo.models import Finding, Test, Engagement

class TestFindingModel(TestCase):

    def test_get_file_path_with_link_no_file_path(self):
        finding = Finding()
        self.assertEqual(None, finding.get_file_path_with_link())
    
    def test_get_file_path_with_link_no_source_code_management_uri(self):
        test = Test()
        engagement = Engagement()
        test.engagement = engagement
        finding = Finding()
        finding.test = test
        finding.file_path = 'FilePath'
        self.assertEqual('FilePath', finding.get_file_path_with_link())

    def test_get_file_path_with_link_and_source_code_management_uri(self):
        test = Test()
        engagement = Engagement()
        test.engagement = engagement
        finding = Finding()
        finding.test = test
        finding.file_path = 'FilePath'
        engagement.source_code_management_uri = 'URL'
        self.assertEqual('<a href=\"URL/FilePath\" target=\"_blank\" title=\"FilePath\">FilePath</a>', finding.get_file_path_with_link())

    def test_get_references_with_links_no_references(self):
        finding = Finding()
        self.assertEqual(None, finding.get_references_with_links())

    def test_get_references_with_links_no_links(self):
        finding = Finding()
        finding.references = 'Lorem ipsum dolor sit amet, consetetur sadipscing elitr'
        self.assertEqual('Lorem ipsum dolor sit amet, consetetur sadipscing elitr', finding.get_references_with_links())

    def test_get_references_with_links_simple_url(self):
        finding = Finding()
        finding.references = 'URL: https://www.example.com'
        self.assertEqual('URL: <a href=\"https://www.example.com\" target=\"_blank\" title=\"https://www.example.com\">https://www.example.com</a>', finding.get_references_with_links())

    def test_get_references_with_links_url_with_port(self):
        finding = Finding()
        finding.references = 'http://www.example.com:8080'
        self.assertEqual('<a href=\"http://www.example.com:8080\" target=\"_blank\" title=\"http://www.example.com:8080\">http://www.example.com:8080</a>', finding.get_references_with_links())

    def test_get_references_with_links_url_with_path(self):
        finding = Finding()
        finding.references = 'URL https://www.example.com/path/part2 behind URL'
        self.assertEqual('URL <a href=\"https://www.example.com/path/part2\" target=\"_blank\" title=\"https://www.example.com/path/part2\">https://www.example.com/path/part2</a> behind URL', finding.get_references_with_links())

    def test_get_references_with_links_complicated_url_with_parameter(self):
        finding = Finding()
        finding.references = 'URL:https://www.example.com/path?param1=abc&_param2=xyz'
        self.assertEqual('URL:<a href=\"https://www.example.com/path?param1=abc&_param2=xyz\" target=\"_blank\" title=\"https://www.example.com/path?param1=abc&_param2=xyz\">https://www.example.com/path?param1=abc&_param2=xyz</a>', finding.get_references_with_links())

    def test_get_references_with_links_two_urls(self):
        finding = Finding()
        finding.references = 'URL1: https://www.example.com URL2: https://info.example.com'
        self.assertEqual('URL1: <a href=\"https://www.example.com\" target=\"_blank\" title=\"https://www.example.com\">https://www.example.com</a> URL2: <a href=\"https://info.example.com\" target=\"_blank\" title=\"https://info.example.com\">https://info.example.com</a>', finding.get_references_with_links())

    def test_get_references_with_links_markdown(self):
        finding = Finding()
        finding.references = 'URL: [https://www.example.com](https://www.example.com)'
        self.assertEqual('URL: [https://www.example.com](https://www.example.com)', finding.get_references_with_links())
