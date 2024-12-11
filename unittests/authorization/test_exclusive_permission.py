import unittest
from unittest.mock import patch, MagicMock
from dojo.models import Dojo_User, Product, ExclusivePermission, Product_Member, Role, Product_Type
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.exclusive_permissions import get_exclusive_permission, RulePermission
from unittests.dojo_test_case import DojoTestCase

class TestExclusivePermissions(DojoTestCase):
    fixtures = ['dojo_testdata.json']

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.get(id=1)
        cls.permission = ExclusivePermission.objects.create(name='Product_Tag_Red_Team', description="view findigns with tags")
        cls.product = Product.objects.create(name='Test Product', prod_type=Product_Type.objects.get(id=1))
        cls.product_member = Product_Member.objects.create(product=cls.product, user=cls.user, role=Role.objects.get(name='Developer'))
        cls.permission.members.add(cls.product_member)

    @patch('dojo.authorization.exclusive_permissions.ExclusivePermission')
    @patch('dojo.authorization.exclusive_permissions.Product_Member')
    def test_get_exclusive_permission(self, mock_product_member, mock_exclusive_permission):
        mock_product_member.objects.filter.return_value.exists.return_value = True
        mock_exclusive_permission.objects.filter.return_value = [self.permission]

        permissions = get_exclusive_permission(self.user, self.product)

        self.assertIn(Permissions.Product_Tag_Red_Team, permissions)

    @patch('dojo.authorization.exclusive_permissions.get_product')
    @patch('dojo.authorization.exclusive_permissions.get_exclusive_permission')
    def test_rule_product_tag_red_team(self, mock_get_exclusive_permission, mock_get_product):
        obj = MagicMock()
        obj.tags.all.return_value = ["red_team"]
        mock_get_product.return_value = self.product
        mock_get_exclusive_permission.return_value = [Permissions.Product_Tag_Red_Team]

        rule_permission = RulePermission(Permissions.Product_Tag_Red_Team, self.user, obj)

        result = rule_permission.rule_Product_Tag_Red_Team()

        self.assertTrue(result)

    @patch('dojo.authorization.exclusive_permissions.get_product')
    @patch('dojo.authorization.exclusive_permissions.get_exclusive_permission')
    def test_rule_product_tag_red_team_no_permission(self, mock_get_exclusive_permission, mock_get_product):
        obj = MagicMock()
        obj.tags.all.return_value = ["red_team"]
        mock_get_product.return_value = self.product
        mock_get_exclusive_permission.return_value = []

        rule_permission = RulePermission(Permissions.Product_Tag_Red_Team, self.user, obj)

        result = rule_permission.rule_Product_Tag_Red_Team()

        self.assertFalse(result)

    def test_rule_product_tag_red_team_no_red_team_tag(self):
        obj = MagicMock()
        obj.tags.all.return_value = ["blue_team"]

        rule_permission = RulePermission(Permissions.Product_Tag_Red_Team, self.user, obj)

        result = rule_permission.rule_Product_Tag_Red_Team()

        self.assertTrue(result)