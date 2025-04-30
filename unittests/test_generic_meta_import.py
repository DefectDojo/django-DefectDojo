import io
import json

from django.conf import settings
from parameterized import parameterized
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import Test, User
from unittests.dojo_test_case import DojoAPITestCase


class TestGenericMetaImports(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        testuser = User.objects.get(username="admin")
        token = Token.objects.get(user=testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        # We must set this to get around forced TLS redirects
        settings.SECURE_SSL_REDIRECT = False

    def _get_base_payload(self, test_label: str):
        return {
            "product_type_name": f"{test_label} Product Type",
            "product_name": f"{test_label} Product",
            "engagement_name": f"{test_label} Engagement",
            "scan_type": "Generic Findings Import",
            "auto_create_context": "true",
            "close_old_findings": "true",
        }

    def _upload_json_as_file(self, data: dict):
        file = io.BytesIO(json.dumps(data).encode("utf-8"))
        file.name = "test.json"
        return file

    def _get_test_object_from_id(self, test_id: int) -> Test:
        return Test.objects.get(id=test_id)

    def _make_assertions(self, test: Test, data: dict) -> None:
        if (description := data.get("description")) is not None:
            self.assertEqual(test.description, description)
        if (static_tool := data.get("static_tool")) is not None:
            self.assertEqual(test.test_type.static_tool, static_tool)
        if (dynamic_tool := data.get("dynamic_tool")) is not None:
            self.assertEqual(test.test_type.dynamic_tool, dynamic_tool)

    @parameterized.expand(
        [
            (
                "Set Description",
                {
                    "description": "some description",
                },
            ),
            (
                "Set Static Tool",
                {
                    "static_tool": True,
                },
            ),
            (
                "Set Dynamic Tool",
                {
                    "dynamic_tool": True,
                },
            ),
            (
                "Set Static Tool + Dynamic Tool",
                {
                    "static_tool": True,
                    "dynamic_tool": True,
                },
            ),
            (
                "Set all the things",
                {
                    "description": "some description",
                    "static_tool": True,
                    "dynamic_tool": True,
                },
            ),
        ],
    )
    def test_value_set_at_import_time(
        self,
        label: str,
        data: dict,
    ):
        payload = self._get_base_payload(label)
        # Construct the extra parts of the request
        file_contents = {
            "name": label,
            "type": f"{label} type",
        }
        # Iterate over the data and set the values in the file
        file_contents.update(
            {key: value for key, value in data.items() if value is not None},
        )
        # Create a pseudo file
        payload["file"] = self._upload_json_as_file(file_contents)
        # import the scan and get the resulting test ID from the response
        test_id = self.import_scan(payload, 201).get("test")
        # Fetch the test from the database
        test = self._get_test_object_from_id(test_id)
        # Make all the appropriate assertions
        self._make_assertions(test, data)

    @parameterized.expand(
        [
            (
                "Update Description",
                {
                    "description_before": "some description",
                    "description_after": "much more detailed description",
                },
            ),
            (
                "Update Static Tool",
                {
                    "static_tool_before": False,
                    "static_tool_after": True,
                },
            ),
            (
                "Update Dynamic Tool",
                {
                    "dynamic_tool_before": True,
                    "dynamic_tool_after": False,
                },
            ),
            (
                "Update Static Tool + Dynamic Tool",
                {
                    "static_tool_before": False,
                    "static_tool_after": True,
                    "dynamic_tool_before": True,
                    "dynamic_tool_after": False,
                },
            ),
            (
                "Update all the things",
                {
                    "description_before": "some description",
                    "description_after": "much more detailed description",
                    "static_tool_before": False,
                    "static_tool_after": True,
                    "dynamic_tool_before": True,
                    "dynamic_tool_after": False,
                },
            ),
        ],
    )
    def test_value_set_at_import_time_then_override_at_reimport(
        self,
        label: str,
        data: dict,
    ):
        payload = self._get_base_payload(label)
        # Construct the extra parts of the request
        file_contents = {
            "name": label,
            "type": f"{label} type",
        }
        # Iterate over the data and set the values in the file
        file_contents.update(
            {key.replace("_before", ""): value for key, value in data.items() if value is not None and "_before" in key},
        )
        # Create a pseudo file
        payload["file"] = self._upload_json_as_file(file_contents)
        # import the scan and get the resulting test ID from the response
        test_id = self.import_scan(payload, 201).get("test")
        # Fetch the test from the database
        test = self._get_test_object_from_id(test_id)
        # Make all the appropriate assertions
        self._make_assertions(test, {key.replace("_before", ""): value for key, value in data.items() if "_before" in key})
        # Update the file with the contents of the changes
        file_contents.update(
            {key.replace("_after", ""): value for key, value in data.items() if value is not None and "_after" in key},
        )
        # Create a pseudo file
        payload["file"] = self._upload_json_as_file(file_contents)
        # reimport the scan and get the resulting test ID from the response
        test_id = self.reimport_scan(payload, 201).get("test")
        # Fetch the test from the database
        test = self._get_test_object_from_id(test_id)
        # Make all the appropriate assertions
        self._make_assertions(test, {key.replace("_after", ""): value for key, value in data.items() if "_after" in key})
