from unittest.mock import patch, MagicMock
from dojo.models import (
    Finding,
    Dojo_User,
    Product,
    ExclusivePermission,
    Product_Member,
    Role,
    Product_Type)
from dojo.api_v2.api_error import ApiError
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.exclusive_permissions import (
    get_exclusive_permission,
    exclude_test_or_finding_with_tag,
    RulePermission
    )
from unittests.dojo_test_case import DojoTestCase

class TestExclusivePermissions(DojoTestCase):
    fixtures = ['dojo_testdata.json']

    @classmethod
    def setUpTestData(cls):
        cls.product = Product.objects.create(
            name='Test Product',
            prod_type=Product_Type.objects.get(id=1))

        cls.user = Dojo_User.objects.get(id=1)

        cls.user_developer = Dojo_User.objects.get(id=2)

        cls.product_member_developer = Product_Member.objects.create(
            product=cls.product,
            user=cls.user_developer,
            role=Role.objects.get(name='Developer'))

        cls.permission = ExclusivePermission.objects.create(
            name='Product_Tag_Red_Team',
            description="view findings with tags",
            validation_field="red_team",
            short_name="red team")


        cls.product_member = Product_Member.objects.create(
            product=cls.product,
            user=cls.user,
            role=Role.objects.get(name='Developer'))

        cls.permission.members.add(cls.product_member)

    @patch('dojo.authorization.exclusive_permissions.ExclusivePermission')
    @patch('dojo.authorization.exclusive_permissions.Product_Member')
    def test_get_exclusive_permission(
            self,
            mock_product_member,
            mock_exclusive_permission):

        mock_product_member.objects.filter.return_value.exists.return_value = True
        mock_exclusive_permission.objects.filter.return_value = [
            self.permission]

        permissions = get_exclusive_permission(self.user, self.product)

        self.assertIn(Permissions.Product_Tag_Red_Team, permissions)

    @patch('dojo.authorization.exclusive_permissions.get_product')
    @patch('dojo.authorization.exclusive_permissions.get_exclusive_permission')
    def test_rule_product_tag_red_team(self,
                                       mock_get_exclusive_permission,
                                       mock_get_product):

        Finding.objects.first().tags.add("red_team")
        obj = Finding.objects.first()
        mock_get_product.return_value = self.product
        mock_get_exclusive_permission.return_value = [
            Permissions.Product_Tag_Red_Team]

        rule_permission = RulePermission(
            Permissions.Product_Tag_Red_Team,
            self.user_developer,
            obj)

        result = rule_permission.rule_Product_Tag_Red_Team()
        self.assertTrue(result)

    @patch('dojo.authorization.exclusive_permissions.get_exclusive_permission')
    def test_rule_product_tag_red_team_no_permission(
            self,
            mock_get_exclusive_permission):

        obj = Finding.objects.first()
        obj.tags.add("red_team")
        mock_get_exclusive_permission.return_value = [
            Permissions.Product_Tag_Red_Team]

        rule_permission = RulePermission(
            Permissions.Product_Tag_Red_Team,
            self.user,
            obj)
        result = rule_permission.rule_Product_Tag_Red_Team()

        self.assertTrue(result)

    @patch('dojo.authorization.exclusive_permissions.get_exclusive_permission')
    def test_rule_product_tag_red_team_no_red_team_tag(
            self,
            mock_get_exclusive_permission):

        mock_get_exclusive_permission.return_value = [
            Permissions.Product_Tag_Red_Team
            ]

        obj = Finding.objects.first()
        rule_permission = RulePermission(Permissions.Product_Tag_Red_Team,
                                         self.product_member,
                                         obj)

        result = rule_permission.rule_Product_Tag_Red_Team()
        self.assertTrue(result)

    @patch('dojo.authorization.exclusive_permissions.ExclusivePermission.objects.get')
    @patch('dojo.authorization.exclusive_permissions.user_has_exclusive_permission')
    def test_exclude_test_or_finding_with_tag(
            self,
            mock_user_has_exclusive_permission,
            mock_exclusive_permission_get,
            ):
        mock_exclusive_permission_get.return_value = self.permission
        mock_user_has_exclusive_permission.return_value = False

        tests_or_findings = MagicMock()
        tests_or_findings.exclude.return_value = tests_or_findings

        result = exclude_test_or_finding_with_tag(tests_or_findings, self.user)

        self.assertEqual(result, tests_or_findings)
        tests_or_findings.exclude.assert_called_once_with(tags__name__in=['red_team'])

    @patch('dojo.authorization.exclusive_permissions.user_has_exclusive_permission')
    def test_exclude_test_or_finding_with_tag_user_has_permission(
            self,
            mock_user_has_exclusive_permission,
            ):

        mock_user_has_exclusive_permission.return_value = True

        findings = Finding.objects.all()
        result = exclude_test_or_finding_with_tag(
            findings,
            product=None,
            user=self.user)

        self.assertEqual(result, findings)

    @patch('dojo.authorization.exclusive_permissions.logger')
    @patch('dojo.authorization.exclusive_permissions.ExclusivePermission.objects.get')
    def test_exclude_test_or_finding_with_tag_permission_not_exist(
            self,
            mock_exclusive_permission_get,
            mock_logger):

        mock_exclusive_permission_get.side_effect = ExclusivePermission.DoesNotExist
        tests_or_findings = Finding.objects.all()
        with self.assertRaises(ApiError):
            exclude_test_or_finding_with_tag(
                tests_or_findings,
                product=None,
                user=self.user)

    def test_exclude_test_or_finding_with_tag_permission_inactive(self):
        self.permission.active = False
        self.permission.save()
        findings = Finding.objects.all()
        result = exclude_test_or_finding_with_tag(
            findings,
            product=None,
            user=self.product_member.user)

        self.assertEqual(result, findings)
