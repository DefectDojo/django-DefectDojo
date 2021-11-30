from ..dojo_test_case import DojoTestCase
from unittest.mock import patch
from dojo.models import Product_Type
from dojo.authorization.roles_permissions import Permissions
from dojo.templatetags.authorization_tags import has_object_permission


class TestAuthorizationTags(DojoTestCase):

    def setUp(self):
        self.product_type = Product_Type()

    @patch('dojo.templatetags.authorization_tags.user_has_permission')
    def test_has_object_permission_no_permission(self, mock_has_permission):
        mock_has_permission.return_value = False

        result = has_object_permission(self.product_type, 'Product_Type_View')

        self.assertFalse(result)
        mock_has_permission.assert_called_with(None, self.product_type, Permissions.Product_Type_View)

    @patch('dojo.templatetags.authorization_tags.user_has_permission')
    def test_has_object_permission_has_permission(self, mock_has_permission):
        mock_has_permission.return_value = True

        result = has_object_permission(self.product_type, 'Product_Type_View')

        self.assertTrue(result)
        mock_has_permission.assert_called_with(None, self.product_type, Permissions.Product_Type_View)

    def test_has_object_permission_wrong_permission(self):

        with self.assertRaises(KeyError):
            result = has_object_permission(self.product_type, 'Test')
