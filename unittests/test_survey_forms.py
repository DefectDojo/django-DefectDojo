import json

from dojo.forms import MultiExampleField, MultiWidgetBasic
from unittests.dojo_test_case import DojoTestCase


class TestSurveyChoiceWidget(DojoTestCase):
    def test_compress_returns_json_string(self):
        field = MultiExampleField(required=False)
        values = ["a", "b", "c", None, None, None]
        compressed = field.compress(values)

        self.assertIsInstance(compressed, str)
        self.assertEqual(json.loads(compressed), values)

    def test_decompress_round_trips(self):
        widget = MultiWidgetBasic()
        values = ["red", "green", "blue", "yellow", None, None]
        compressed = json.dumps(values)

        self.assertEqual(widget.decompress(compressed), values)

    def test_decompress_empty_returns_blank_list(self):
        widget = MultiWidgetBasic()
        self.assertEqual(widget.decompress(None), [None, None, None, None, None, None])
        self.assertEqual(widget.decompress(""), [None, None, None, None, None, None])

    def test_no_pickle_in_form_module(self):
        """Guard test: pickle must not be reintroduced into dojo/forms.py."""
        from pathlib import Path

        forms_path = Path(__file__).resolve().parent.parent / "dojo" / "forms.py"
        contents = forms_path.read_text()
        self.assertNotIn("import pickle", contents)
        self.assertNotIn("pickle.loads", contents)
        self.assertNotIn("pickle.dumps", contents)
