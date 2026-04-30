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
