import unittest
from django.template import Context, Template
from dojo.templatetags.display_tags import render_exclusive_permission_for_member
from dojo.models import ExclusivePermission


class DisplayTags(unittest.TestCase):
    def test_render_exclusive_permission_for_member(self):
        permissions = [ExclusivePermission("Permission 1", "description 1"),
                       ExclusivePermission("Permission 2", "description 2"),
                       ExclusivePermission("Permission 3", "description 3")]
        
        result = render_exclusive_permission_for_member(permissions)
        
        expected_result = (
            "<span class='pass_fail Pass'>Permission 1</span><br/>"
            "<span class='pass_fail Pass'>Permission 2</span><br/>"
            "<span class='pass_fail Pass'>Permission 3</span><br/>"
        )
        
        self.assertEqual(result, expected_result)