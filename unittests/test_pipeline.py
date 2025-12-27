
import unittest
from unittest.mock import ANY, MagicMock, patch

from social_core.backends.azuread_tenant import AzureADTenantOAuth2
from social_core.backends.open_id_connect import OpenIdConnectAuth

from dojo.models import Dojo_Group
from dojo.pipeline import update_azure_groups, update_oidc_groups


class TestUpdateOIDCGroups(unittest.TestCase):

    @patch("dojo.pipeline.settings")
    @patch("dojo.pipeline.assign_user_to_groups")
    @patch("dojo.pipeline.cleanup_old_groups_for_user")
    def test_update_oidc_groups_with_valid_groups(self, mock_cleanup, mock_assign, mock_settings):
        mock_settings.OIDC_AUTH_ENABLED = True
        mock_settings.OIDC_GET_GROUPS = True
        mock_settings.OIDC_GROUPS_FILTER = ".*"
        mock_settings.OIDC_CLEANUP_GROUPS = True
        mock_backend = MagicMock(spec=OpenIdConnectAuth)
        mock_user = MagicMock()
        response = {"groups": ["admin", "user"]}
        update_oidc_groups(mock_backend, uid="123", user=mock_user, response=response)
        mock_assign.assert_called_once_with(mock_user, ["admin", "user"], ANY)
        mock_cleanup.assert_called_once_with(mock_user, ["admin", "user"])

    @patch("dojo.pipeline.settings")
    def test_update_oidc_groups_with_no_groups(self, mock_settings):
        mock_settings.OIDC_AUTH_ENABLED = True
        mock_settings.OIDC_GET_GROUPS = True
        mock_backend = MagicMock(spec=OpenIdConnectAuth)
        mock_user = MagicMock()
        response = {"groups": []}
        with patch("dojo.pipeline.logger.warning") as mock_logger:
            update_oidc_groups(mock_backend, uid="123", user=mock_user, response=response)
            mock_logger.assert_called_once_with("No 'groups' claim found in OIDC response. Skipping group assignment.")

    @patch("dojo.pipeline.settings")
    @patch("dojo.pipeline.assign_user_to_groups")
    def test_update_oidc_groups_with_filter(self, mock_assign, mock_settings):
        mock_settings.OIDC_AUTH_ENABLED = True
        mock_settings.OIDC_GET_GROUPS = True
        mock_settings.OIDC_GROUPS_FILTER = "^admin$"
        mock_settings.OIDC_CLEANUP_GROUPS = False
        mock_backend = MagicMock(spec=OpenIdConnectAuth)
        mock_user = MagicMock()
        response = {"groups": ["admin", "user", "guest"]}
        update_oidc_groups(mock_backend, uid="123", user=mock_user, response=response)
        mock_assign.assert_called_once_with(mock_user, ["admin"], ANY)


class TestUpdateAzureGroups(unittest.TestCase):

    @patch("dojo.pipeline.settings")
    @patch("dojo.pipeline.assign_user_to_groups")
    @patch("dojo.pipeline.cleanup_old_groups_for_user")
    @patch("dojo.pipeline.requests.get")
    def test_update_azure_groups_with_group_ids(self, mock_requests_get, mock_cleanup, mock_assign, mock_settings):
        mock_settings.AZUREAD_TENANT_OAUTH2_ENABLED = True
        mock_settings.AZUREAD_TENANT_OAUTH2_GET_GROUPS = True
        mock_settings.AZUREAD_TENANT_OAUTH2_GROUPS_FILTER = None
        mock_settings.AZUREAD_TENANT_OAUTH2_CLEANUP_GROUPS = True
        mock_settings.REQUESTS_TIMEOUT = 5
        mock_backend = MagicMock(spec=AzureADTenantOAuth2)
        mock_user = MagicMock()
        mock_social = MagicMock()
        mock_social.extra_data = {
            "access_token": "fake-token",
            "resource": "https://graph.microsoft.com",
        }
        mock_user.social_auth.order_by.return_value.first.return_value = mock_social
        mock_response = {"groups": ["group-id-1", "group-id-2"]}
        mock_requests_get.return_value.json.return_value = {"displayName": "GroupName"}
        mock_requests_get.return_value.raise_for_status = MagicMock()
        with patch("dojo.pipeline.is_group_id", return_value=True):
            update_azure_groups(mock_backend, uid="123", user=mock_user, response=mock_response)
        mock_assign.assert_called_once_with(mock_user, ["GroupName", "GroupName"], Dojo_Group.AZURE)
        mock_cleanup.assert_called_once_with(mock_user, ["GroupName", "GroupName"])

    @patch("dojo.pipeline.settings")
    def test_update_azure_groups_with_no_groups(self, mock_settings):
        mock_settings.AZUREAD_TENANT_OAUTH2_ENABLED = True
        mock_settings.AZUREAD_TENANT_OAUTH2_GET_GROUPS = True
        mock_backend = MagicMock(spec=AzureADTenantOAuth2)
        mock_user = MagicMock()
        mock_user.social_auth.order_by.return_value.first.return_value = MagicMock()
        mock_response = {"groups": []}
        with patch("dojo.pipeline.logger.warning") as mock_logger:
            update_azure_groups(mock_backend, uid="123", user=mock_user, response=mock_response)
            mock_logger.assert_called_once_with("No groups in response. Stopping to update groups of user based on azureAD")

    @patch("dojo.pipeline.settings")
    @patch("dojo.pipeline.assign_user_to_groups")
    def test_update_azure_groups_with_group_name_and_filter(self, mock_assign, mock_settings):
        mock_settings.AZUREAD_TENANT_OAUTH2_ENABLED = True
        mock_settings.AZUREAD_TENANT_OAUTH2_GET_GROUPS = True
        mock_settings.AZUREAD_TENANT_OAUTH2_GROUPS_FILTER = "^admin$"
        mock_settings.AZUREAD_TENANT_OAUTH2_CLEANUP_GROUPS = False
        mock_backend = MagicMock(spec=AzureADTenantOAuth2)
        mock_user = MagicMock()
        mock_social = MagicMock()
        mock_social.extra_data = {"access_token": "fake-token", "resource": "https://graph.microsoft.com"}
        mock_user.social_auth.order_by.return_value.first.return_value = mock_social
        mock_response = {"groups": ["admin", "user", "guest"]}
        with patch("dojo.pipeline.is_group_id", return_value=False):
            update_azure_groups(mock_backend, uid="123", user=mock_user, response=mock_response)
        mock_assign.assert_called_once_with(mock_user, ["admin"], Dojo_Group.AZURE)
