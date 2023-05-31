from .dojo_test_case import DojoTestCase
from django.conf import settings
from social_core.backends.azuread_tenant import AzureADTenantOAuth2
from django.contrib.auth import get_user_model
from social_django.models import UserSocialAuth
from unittest import mock
from dojo.pipeline import update_product_type_azure_devops
from azure.devops.v7_1.graph.models import GraphSubject, GraphGroup
from dojo.models import Product_Type_Member
import logging
from io import StringIO


class PipelineTest(DojoTestCase):
    def setUp(self):
        settings.AZUREAD_TENANT_OAUTH2_ENABLED = True
        settings.AZURE_DEVOPS_PERMISSION_AUTO_IMPORT = True
        settings.AZURE_DEVOPS_ORGANIZATION_URL = "https://vsaex.dev.azure.com/test"
        settings.AZURE_DEVOPS_TOKEN = "test"
        settings.AZURE_DEVOPS_MAIN_SECURITY_GROUP = "dummy_group_name"
        settings.AZURE_DEVOPS_GROUP_TEAM_FILTERS = "[A-Za-z0-9]+.\\s-\\s.+//^(CDE|EVC)\\s.*"
        settings.AZURE_DEVOPS_OFFICES_LOCATION = "office1,office2"
        settings.AZURE_DEVOPS_JOBS_TITLE = "test job"

    def dummy_search_azure_groups(self, *args, **kwargs):
        return ["dummy_group_name"]

    def mock_graph_client(self, *args, **kwargs):
        mock_graph_client = mock.Mock
        mock_graph_client.return_value = mock_graph_client
        mock_graph_client.query_subjects = mock.Mock()
        mock_result_subject = [GraphSubject(descriptor="test_descriptor")]
        mock_graph_client.query_subjects.return_value = mock_result_subject
        mock_graph_client.get_membership = mock.Mock()
        mock_membership = mock.Mock()
        mock_membership.additional_properties = {"value": [{"containerDescriptor": "test"}]}
        mock_graph_client.get_membership.return_value = mock_membership
        mock_graph_client.get_group = mock.Mock()
        mock_graph_client.get_group.return_value = GraphGroup(display_name="test - test", descriptor="test")
        mock_graph_client.get_group.return_value = GraphGroup(display_name="CDE - test", descriptor="test")
        return mock_graph_client

    def _mock_response(
        self,
        status=200,
        content="CONTENT",
        json_data=None,
        raise_for_status=None,
    ):
        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status
        mock_resp.status_code = status
        mock_resp.content = content
        if json_data:
            mock_resp.json = mock.Mock(return_value=json_data)
        return mock_resp

    def test_error_call_microsoft_grapqh_update_product_type_azure_devops(self):
        user_model = get_user_model()
        user = user_model._default_manager.create_user(username="test", password="pwd")
        UserSocialAuth.objects.create(
            user=user, provider="azuread-oauth2", extra_data={"access_token": "test", "resource": "url_graph"}
        )
        self.client.login(username="test", password="pwd")
        kwargs = {"response": {"groups": ["b3febafa-3330-4205-b40d-59cc508ef097"]}}

        capture = StringIO()
        logger = logging.getLogger("dojo.pipeline")
        handler = logging.StreamHandler(capture)
        logger.addHandler(handler)

        update_product_type_azure_devops(AzureADTenantOAuth2(), None, user, None, None, **kwargs)
        self.assertEqual(
            capture.getvalue().strip().split("\n"),
            ["Could not call microsoft graph API or save groups to member"],
        )

    @mock.patch("dojo.pipeline.search_azure_groups", dummy_search_azure_groups)
    @mock.patch("requests.get")
    @mock.patch("azure.devops.connection.Connection.get_client", mock_graph_client)
    def test_ok_update_product_type_azure_devops(self, mock_get):
        user_model = get_user_model()
        user = user_model._default_manager.create_user(username="test", password="pwd")
        UserSocialAuth.objects.create(
            user=user,
            provider="azuread-oauth2",
            extra_data={"access_token": "test", "resource": "https://graph.microsoft.com"},
        )
        self.client.login(username="test", password="pwd")
        kwargs = {
            "response": {"groups": ["b3febafa-3330-4205-b40d-59cc508ef097"]},
            "details": {"email": "test@email.com"},
        }

        mock_resp = self._mock_response(json_data={"jobTitle": "testjobTitle", "officeLocation": "testofficeLocation"})
        mock_get.return_value = mock_resp

        update_product_type_azure_devops(AzureADTenantOAuth2(), None, user, None, None, **kwargs)
        user_product_types_names = [
            prod.product_type.name for prod in Product_Type_Member.objects.select_related("user").filter(user=user)
        ]
        self.assertEqual(user_product_types_names, ["CDE - test"])
