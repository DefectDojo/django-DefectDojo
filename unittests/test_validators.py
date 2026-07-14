from django.core.exceptions import ValidationError

from dojo.validators import clean_tags
from unittests.dojo_test_case import DojoTestCase


class TestCleanTags(DojoTestCase):

    def test_clean_tags_string(self):
        self.assertEqual("simple_tag", clean_tags("simple tag"))

    def test_clean_tags_list(self):
        self.assertEqual(["tag_one", "tag_two"], clean_tags(["tag one", "tag,two"]))

    def test_clean_tags_empty_values(self):
        self.assertEqual([], clean_tags([]))
        self.assertEqual("", clean_tags(""))
        self.assertIsNone(clean_tags(None))

    def test_clean_tags_list_with_none_entries(self):
        """
        Parsers can emit None tags (e.g. Trivy legacy reports without a
        "Class" field). clean_tags must filter them out instead of raising
        TypeError from the regex (see import pipeline crash in
        default_importer._process_findings_internal).
        """
        self.assertEqual(["os-pkgs"], clean_tags(["os-pkgs", None]))
        self.assertEqual([], clean_tags([None, None]))

    def test_clean_tags_invalid_type_raises(self):
        with self.assertRaises(ValidationError):
            clean_tags(42)
