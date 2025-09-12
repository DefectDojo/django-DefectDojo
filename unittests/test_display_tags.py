import unittest
from django.template import Context, Template
from dojo.templatetags.display_tags import (
    render_exclusive_permission_for_member,
    render_risk_acceptance_accepted_by)
from dojo.models import ExclusivePermission
from dojo.models import Finding
from .dojo_test_case import DojoTestCase


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


class RenderRiskAcceptanceAcceptedByTests(DojoTestCase):

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.finding = Finding.objects.get(id=226)
        self.risk_acceptance = self.finding.risk_acceptance

    def test_render_risk_acceptance_single_user(self):
        """Test with a single accepted user"""
        self.finding.accepted_by = "JohnSmith"
        self.risk_acceptance.accepted_by = "['JohnSmith']"
        self.risk_acceptance.save()
        self.finding.save()
        result = render_risk_acceptance_accepted_by(self.finding)
        self.assertIn("👤 John Smith ✅", result)

    def test_render_risk_acceptance_multiple_users(self):
        """Test with multiple accepted users"""
        self.finding.accepted_by = "JohnSmith, JaneDoe"
        self.risk_acceptance.accepted_by = "['JohnSmith', 'JaneDoe']"
        self.risk_acceptance.save()
        self.finding.save()
        result = render_risk_acceptance_accepted_by(self.finding)
        self.assertIn("👤 John Smith ✅", result)
        self.assertIn("👤 Jane Doe ✅", result)

    def test_render_risk_acceptance_pending_user(self):
        """Test with a pending user"""
        self.finding.accepted_by = ""
        self.risk_acceptance.accepted_by = "['JohnSmith', 'JaneDoe']"
        self.risk_acceptance.save()
        self.finding.save()
        result = render_risk_acceptance_accepted_by(self.finding)
        self.assertIn("👤 John Smith ⏳", result)
        self.assertIn("👤 Jane Doe ⏳", result)

    def test_render_risk_acceptance_maintainer(self):
        """Test with an user maintainer"""
        self.finding.accepted_by = "UserMaintainer"
        self.risk_acceptance.accepted_by = "['JohnSmith', 'JaneDoe']"
        self.risk_acceptance.save()
        self.finding.save()
        result = render_risk_acceptance_accepted_by(self.finding)
        self.assertIn("👤 John Smith ✅", result)
        self.assertIn("👤 Jane Doe ✅", result)
