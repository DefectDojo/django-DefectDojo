import json
import os
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError
from django.test import SimpleTestCase, override_settings

import dojo.api_v2.ia_recommendation.helper as helper

MODULE = "dojo.api_v2.ia_recommendation.helper"


def _client_error():
    return ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "Converse")


class TestIaRecommendationDispatcher(SimpleTestCase):

    @override_settings(IA_PROVIDER="AWSBEDROCK")
    @patch(f"{MODULE}._async_get_ia_recommendation_marvin")
    @patch(f"{MODULE}.async_get_aws_bedrock_recommendation")
    def test_aws_bedrock_provider_uses_bedrock_flow(self, mock_bedrock, mock_marvin):
        helper.async_get_ia_recommendation("1", "user", False)

        mock_bedrock.assert_called_once_with("1", "user", False)
        mock_marvin.assert_not_called()

    @override_settings(IA_PROVIDER=" awsbedrock ")
    @patch(f"{MODULE}._async_get_ia_recommendation_marvin")
    @patch(f"{MODULE}.async_get_aws_bedrock_recommendation")
    def test_provider_is_case_and_whitespace_insensitive(self, mock_bedrock, mock_marvin):
        helper.async_get_ia_recommendation("1", "user", True)

        mock_bedrock.assert_called_once_with("1", "user", True)
        mock_marvin.assert_not_called()

    @override_settings(IA_PROVIDER="")
    @patch(f"{MODULE}._async_get_ia_recommendation_marvin")
    @patch(f"{MODULE}.async_get_aws_bedrock_recommendation")
    def test_other_provider_uses_existing_flow(self, mock_bedrock, mock_marvin):
        helper.async_get_ia_recommendation("1", "user", True)

        mock_marvin.assert_called_once_with("1", "user", True)
        mock_bedrock.assert_not_called()


class TestGetAwsBedrockApiKey(SimpleTestCase):

    @override_settings(AWS_REGION="us-east-1", AWS_BEDROCK_SECRET_NAME="bedrock/secret")
    @patch(f"{MODULE}.boto3")
    def test_reads_api_key_from_secret(self, mock_boto3):
        secrets = MagicMock()
        secrets.get_secret_value.return_value = {"SecretString": json.dumps({"api-key": "the-key"})}
        mock_boto3.client.return_value = secrets

        result = helper._get_aws_bedrock_api_key()

        self.assertEqual(result, "the-key")
        mock_boto3.client.assert_called_once_with("secretsmanager", region_name="us-east-1")
        secrets.get_secret_value.assert_called_once_with(SecretId="bedrock/secret")

    @override_settings(AWS_REGION="us-east-1", AWS_BEDROCK_SECRET_NAME="bedrock/secret")
    @patch(f"{MODULE}.boto3")
    def test_missing_api_key_field_raises_key_error(self, mock_boto3):
        secrets = MagicMock()
        secrets.get_secret_value.return_value = {"SecretString": json.dumps({"other": "x"})}
        mock_boto3.client.return_value = secrets

        with self.assertRaises(KeyError):
            helper._get_aws_bedrock_api_key()


class TestGetFirstAwsBedrockModelId(SimpleTestCase):

    @override_settings(AWS_REGION="us-east-1")
    @patch(f"{MODULE}.boto3")
    def test_returns_first_inference_profile(self, mock_boto3):
        control = MagicMock()
        control.list_inference_profiles.return_value = {
            "inferenceProfileSummaries": [
                {"inferenceProfileId": "us.first"},
                {"inferenceProfileId": "us.second"},
            ]
        }
        mock_boto3.client.return_value = control

        self.assertEqual(helper._get_first_aws_bedrock_model_id(), "us.first")
        mock_boto3.client.assert_called_once_with("bedrock", region_name="us-east-1")

    @override_settings(AWS_REGION="us-east-1")
    @patch(f"{MODULE}.boto3")
    def test_no_profiles_raises_index_error(self, mock_boto3):
        control = MagicMock()
        control.list_inference_profiles.return_value = {"inferenceProfileSummaries": []}
        mock_boto3.client.return_value = control

        with self.assertRaises(IndexError):
            helper._get_first_aws_bedrock_model_id()


@override_settings(AWS_REGION="us-east-1")
class TestAsyncGetAwsBedrockRecommendation(SimpleTestCase):

    def setUp(self):
        self.user = MagicMock(username="tester")
        self.finding_patch = patch(f"{MODULE}.Finding")
        self.mock_finding = self.finding_patch.start()
        self.mock_finding.objects.filter.return_value = []
        self.addCleanup(self.finding_patch.stop)

        self.env_patch = patch.dict(os.environ, {}, clear=False)
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def _converse_response(self, text):
        return {"output": {"message": {"content": [{"text": text}]}}}

    @patch(f"{MODULE}.http_response")
    @patch(f"{MODULE}.boto3")
    @patch(f"{MODULE}._get_first_aws_bedrock_model_id", return_value="us.profile")
    @patch(f"{MODULE}._get_aws_bedrock_api_key", return_value="the-key")
    def test_success_sets_bearer_token_and_uses_first_model(
        self, mock_key, mock_model, mock_boto3, mock_http_response,
    ):
        runtime = MagicMock()
        runtime.converse.return_value = self._converse_response("recommendation text")
        mock_boto3.client.return_value = runtime

        helper.async_get_aws_bedrock_recommendation("1", self.user, save=False)

        self.assertEqual(os.environ["AWS_BEARER_TOKEN_BEDROCK"], "the-key")
        mock_boto3.client.assert_called_with("bedrock-runtime", region_name="us-east-1")
        runtime.converse.assert_called_once()
        self.assertEqual(runtime.converse.call_args.kwargs["modelId"], "us.profile")
        mock_http_response.ok.assert_called_once_with(message="OK", data=None)
        mock_http_response.error.assert_not_called()

    @patch(f"{MODULE}.finding_helper")
    @patch(f"{MODULE}.get_object_or_404")
    @patch(f"{MODULE}.http_response")
    @patch(f"{MODULE}.boto3")
    @patch(f"{MODULE}._get_first_aws_bedrock_model_id", return_value="us.profile")
    @patch(f"{MODULE}._get_aws_bedrock_api_key", return_value="the-key")
    def test_save_stores_recommendation_on_finding(
        self, mock_key, mock_model, mock_boto3, mock_http_response, mock_get_404, mock_finding_helper,
    ):
        runtime = MagicMock()
        runtime.converse.return_value = self._converse_response("saved text")
        mock_boto3.client.return_value = runtime
        finding = MagicMock(ia_recommendation=None)
        mock_get_404.return_value = finding

        helper.async_get_aws_bedrock_recommendation("7", self.user, save=True)

        self.assertEqual(finding.ia_recommendation["data"]["recommendations"], "saved text")
        self.assertEqual(finding.ia_recommendation["data"]["user"], "tester")
        self.assertIsNone(finding.ia_recommendation["data"]["like_status"])
        finding.save.assert_called_once_with(update_fields=["ia_recommendation"])
        mock_finding_helper.parser_ia_recommendation.assert_called_once_with(finding.ia_recommendation)

    @patch(f"{MODULE}.http_response")
    @patch(f"{MODULE}.boto3")
    @patch(f"{MODULE}._get_first_aws_bedrock_model_id", return_value="us.profile")
    @patch(f"{MODULE}._get_aws_bedrock_api_key", return_value="the-key")
    def test_bedrock_client_error_returns_error_response(
        self, mock_key, mock_model, mock_boto3, mock_http_response,
    ):
        runtime = MagicMock()
        runtime.converse.side_effect = _client_error()
        mock_boto3.client.return_value = runtime

        helper.async_get_aws_bedrock_recommendation("1", self.user, save=False)

        mock_http_response.error.assert_called_once()
        self.assertEqual(mock_http_response.error.call_args.kwargs["message"], "Error AWS Bedrock")
        mock_http_response.ok.assert_not_called()

    @patch(f"{MODULE}.http_response")
    @patch(f"{MODULE}.boto3")
    @patch(f"{MODULE}._get_first_aws_bedrock_model_id", return_value="us.profile")
    @patch(f"{MODULE}._get_aws_bedrock_api_key", side_effect=ValueError("bad json"))
    def test_invalid_secret_json_returns_error_response(
        self, mock_key, mock_model, mock_boto3, mock_http_response,
    ):
        helper.async_get_aws_bedrock_recommendation("1", self.user, save=False)

        mock_http_response.error.assert_called_once()
        mock_boto3.client.assert_not_called()

    @patch(f"{MODULE}.http_response")
    @patch(f"{MODULE}.boto3")
    @patch(f"{MODULE}._get_first_aws_bedrock_model_id", return_value="us.profile")
    @patch(f"{MODULE}._get_aws_bedrock_api_key", return_value="the-key")
    def test_unexpected_response_shape_returns_error_response(
        self, mock_key, mock_model, mock_boto3, mock_http_response,
    ):
        runtime = MagicMock()
        runtime.converse.return_value = {"output": {}}
        mock_boto3.client.return_value = runtime

        helper.async_get_aws_bedrock_recommendation("1", self.user, save=False)

        mock_http_response.error.assert_called_once()
