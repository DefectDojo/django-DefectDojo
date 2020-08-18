from django.test import TestCase
from dojo.tools.semgrep.helpers import create_dedupe_key, _format_by_type

class TestSemgrepHelpers(TestCase):

    def test_dedupe_same_inputs(self):
        x = create_dedupe_key('a', 'b', 'c', 'd')
        y = create_dedupe_key('a', 'b', 'c', 'd')
        self.assertEqual(x, y)

    def test_dedupe_different_inputs(self):
        x = create_dedupe_key('a', 'b', 'c', 'd')
        y = create_dedupe_key('d', 'b', 'c', 'a')
        self.assertNotEqual(x, y)

    def test_format_by_type_string(self):
        input = 'example'
        self.assertEqual(input, _format_by_type(input))

    def test_format_by_type_list(self):
        input = ['x', 'y', 'z']
        result = 'x y z'
        self.assertEqual(result, _format_by_type(input)) 

    def test_format_by_type_dict(self):
        input = {'x': 1, 'y': 2, 'z': 3}
        result = 'x: 1 y: 2 z: 3'
        self.assertEqual(result, _format_by_type(input)) 

    def test_format_by_type_invalid_input(self):
        input = -1
        self.assertEqual(None, _format_by_type(input))