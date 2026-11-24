from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock, patch

from django.test import TestCase

from dojo.azure_devops_helper import AzureDevOpsWorkItemHelper


class TestAzureDevOpsWorkItemHelper(TestCase):
    def setUp(self):
        self.helper = AzureDevOpsWorkItemHelper()
        self.user = SimpleNamespace(username="tester", email="tester@example.com")

    @patch.object(AzureDevOpsWorkItemHelper, "_get_description_DOR", return_value="desc dor")
    @patch.object(AzureDevOpsWorkItemHelper, "_get_profile_connection")
    @patch.object(AzureDevOpsWorkItemHelper, "_get_connection")
    @patch.object(AzureDevOpsWorkItemHelper, "_project", new_callable=PropertyMock)
    @patch.object(AzureDevOpsWorkItemHelper, "_team_name", new_callable=PropertyMock)
    @patch.object(AzureDevOpsWorkItemHelper, "_work_item_type", new_callable=PropertyMock)
    def test_returns_existing_active_work_item_id(
        self,
        mock_work_item_type,
        mock_team_name,
        mock_project,
        mock_get_connection,
        mock_get_profile_connection,
        _mock_desc,
    ):
        mock_work_item_type.return_value = "Task"
        mock_team_name.return_value = "team"
        mock_project.return_value = "project"

        conn = MagicMock()
        mock_get_connection.return_value = conn
        wit_client = conn.clients.get_work_item_tracking_client.return_value
        work_client = conn.clients.get_work_client.return_value
        work_client.get_team_field_values.return_value = SimpleNamespace(default_value="project\\area")
        work_client.get_team_iterations.return_value = [SimpleNamespace(path="project\\Sprint 1")]
        wit_client.query_by_wiql.return_value = SimpleNamespace(work_items=[SimpleNamespace(id=99)])
        wit_client.get_work_item.return_value = SimpleNamespace(fields={"System.State": "Active"})

        profile_conn = MagicMock()
        mock_get_profile_connection.return_value = profile_conn
        profile_conn.clients.get_profile_client.return_value.get_profile.return_value = SimpleNamespace(
            additional_properties={}
        )

        result = self.helper.get_or_create_work_item(
            title="Request Peer Review 123",
            description="desc",
            user=self.user,
            evidence_and_image=None,
            finding=1,
        )

        self.assertEqual(result, "99")
        wit_client.create_work_item.assert_not_called()

    @patch.object(AzureDevOpsWorkItemHelper, "_get_description_DOR", return_value="desc dor")
    @patch.object(AzureDevOpsWorkItemHelper, "_get_profile_connection")
    @patch.object(AzureDevOpsWorkItemHelper, "_get_connection")
    @patch.object(AzureDevOpsWorkItemHelper, "_project", new_callable=PropertyMock)
    @patch.object(AzureDevOpsWorkItemHelper, "_team_name", new_callable=PropertyMock)
    @patch.object(AzureDevOpsWorkItemHelper, "_work_item_type", new_callable=PropertyMock)
    def test_reactivates_closed_existing_work_item(
        self,
        mock_work_item_type,
        mock_team_name,
        mock_project,
        mock_get_connection,
        mock_get_profile_connection,
        _mock_desc,
    ):
        mock_work_item_type.return_value = "Task"
        mock_team_name.return_value = "team"
        mock_project.return_value = "project"

        conn = MagicMock()
        mock_get_connection.return_value = conn
        wit_client = conn.clients.get_work_item_tracking_client.return_value
        work_client = conn.clients.get_work_client.return_value
        work_client.get_team_field_values.return_value = SimpleNamespace(default_value="project\\area")
        work_client.get_team_iterations.return_value = [SimpleNamespace(path="project\\Sprint 1")]
        wit_client.query_by_wiql.return_value = SimpleNamespace(work_items=[SimpleNamespace(id=77)])
        wit_client.get_work_item.return_value = SimpleNamespace(fields={"System.State": "Closed"})

        profile_conn = MagicMock()
        mock_get_profile_connection.return_value = profile_conn
        profile_conn.clients.get_profile_client.return_value.get_profile.return_value = SimpleNamespace(
            additional_properties={}
        )

        result = self.helper.get_or_create_work_item(
            title="Request Peer Review 123",
            description="desc",
            user=self.user,
            evidence_and_image=None,
            finding=1,
        )

        self.assertEqual(result, "77")
        wit_client.update_work_item.assert_called_once()
        wit_client.create_work_item.assert_not_called()
