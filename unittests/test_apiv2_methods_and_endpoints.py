import django.apps

from dojo.api_v2 import serializers
from dojo.models import (
    CWE,
    BannerConf,
    Benchmark_Category,
    Benchmark_Product,
    Benchmark_Product_Summary,
    Benchmark_Requirement,
    Benchmark_Type,
    Choice,
    Contact,
    FileAccessToken,
    GITHUB_Clone,
    GITHUB_Conf,
    GITHUB_Details_Cache,
    GITHUB_Issue,
    GITHUB_PKey,
    Objects_Product,
    Objects_Review,
    Product_Line,
    Report_Type,
    Testing_Guide,
    Testing_Guide_Category,
    Tool_Product_History,
    UserAnnouncement,
    TransferFindingFinding,
    TransferFinding,
    PermissionKey,
    ExclusivePermission,
)
from dojo.urls import v2_api

from .dojo_test_case import DojoTestCase
from .test_rest_framework import BASE_API_URL, get_open_api3_json_schema


class ApiEndpointMethods(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()

        self.schema = get_open_api3_json_schema()

        self.registry = v2_api.registry

    def test_is_defined(self):
        exempt_list = [
            "import-scan", "reimport-scan", "notes", "system_settings", "roles",
            "import-languages", "endpoint_meta_import", "test_types",
            "configuration_permissions", "questionnaire_questions",
            "questionnaire_answers", "questionnaire_answered_questionnaires",
            "questionnaire_engagement_questionnaires", "questionnaire_general_questionnaires",
            "dojo_group_members", "product_members", "product_groups", "product_type_groups",
            "product_type_members", "components"
        ]
        for reg, _, _ in sorted(self.registry):
            if reg in exempt_list:
                continue
            for method in ["get", "post"]:
                self.assertIsNotNone(
                    self.schema["paths"][f"{BASE_API_URL}/{reg}/"].get(method),
                    f"Endpoint: {reg}, Method: {method}",
                )

            for method in ["get", "put", "patch", "delete"]:
                self.assertIsNotNone(
                    self.schema["paths"][f"{BASE_API_URL}/{reg}" + "/{id}/"].get(method),
                    f"Endpoint: {reg}, Method: {method}",
                )

            self.assertIsNotNone(
                self.schema["paths"]
                .get(f"{BASE_API_URL}/{reg}" + "/{id}/delete_preview/", {})
                .get("get"),
                f"Endpoint: {reg}, Method: get - delete_preview",
            )


class ApiEndpoints(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()

        self.used_models = []
        for serializer in serializers.__dict__.values():
            if hasattr(serializer, "Meta"):
                if hasattr(serializer.Meta, "model"):
                    self.used_models.append(serializer.Meta.model)
        self.no_api_models = [  # TODO: these models are excluded from check for now but implementation is needed
            Contact,
            Product_Line,
            Report_Type,
            CWE,
            FileAccessToken,
            UserAnnouncement,
            BannerConf,
            GITHUB_Conf,
            GITHUB_Issue,
            GITHUB_Clone,
            GITHUB_Details_Cache,
            GITHUB_PKey,
            Tool_Product_History,
            Objects_Review,
            Objects_Product,
            Testing_Guide_Category,
            Testing_Guide,
            Benchmark_Type,
            Benchmark_Category,
            Benchmark_Requirement,
            Benchmark_Product,
            Benchmark_Product_Summary,
            Choice,
            TransferFindingFinding,
            PermissionKey,
            ExclusivePermission,
        ]

    def test_is_defined(self):
        for subclass in django.apps.apps.get_models():
            if subclass.__module__ == "dojo.models":
                if (subclass.__name__[:9] == "Tagulous_") and (subclass.__name__[-5:] == "_tags"):
                    continue
                if subclass.__name__ == "Alerts":
                    continue
                with self.subTest(subclass=subclass):
                    if subclass in self.used_models:
                        self.assertNotIn(subclass, self.no_api_models, "Thank you, you just implemented API endpoint for the model which was needed. Please remove it from exception list 'self.no_api_models'")
                    if subclass not in self.no_api_models:
                        self.assertIn(subclass, self.used_models, "API endpoint for the managing mentioned model is need")
