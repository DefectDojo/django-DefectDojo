import unittest
from django.template import Context, Template
from dojo.templatetags.display_tags import render_exclusive_permission_for_member
from dojo.models import ExclusivePermission


class DisplayTags(unittest.TestCase):
    def test_render_exclusive_permission_for_member(self):
        permissions = [ExclusivePermission(name="Permission 1",
                                           short_name="description 1"),
                       ExclusivePermission(name="Permission 2",
                                           short_name="description 2"),
                       ExclusivePermission(name="Permission 3",
                                           short_name="description 3")]
        
        result = render_exclusive_permission_for_member(permissions)
        
        expected_result = (
            "<span class='pass_fail Pass'>description 1</span>"
            "<span class='pass_fail Pass'>description 2</span>"
            "<span class='pass_fail Pass'>description 3</span>")
        self.assertEqual(result, expected_result)
