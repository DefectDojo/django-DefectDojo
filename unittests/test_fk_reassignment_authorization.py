"""
Regression tests for cross-tenant FK authorization of the REST API.

Covers two validation paths for FKs referenced by the serializer:

1. **PUT/PATCH reassignment** — a user with edit on a source object
   re-parents it into a tenant they have no membership on.

2. **POST cross-tenant linking** — a create payload references a
   sibling FK pointing at someone else's tenant (e.g. a Test whose
   ``api_scan_configuration`` belongs to another asset).
"""
import base64
import datetime

from django.conf import settings
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.authorization.models import (
    Product_Member,
    Product_Type_Member,
    Role,
)
from dojo.models import (
    App_Analysis,
    BurpRawRequestResponse,
    Dojo_User,
    Endpoint,
    Endpoint_Status,
    Engagement,
    Engagement_Presets,
    Finding,
    JIRA_Instance,
    JIRA_Issue,
    JIRA_Project,
    Language_Type,
    Languages,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Test,
    Test_Type,
    Tool_Configuration,
    Tool_Product_Settings,
    Tool_Type,
)

from .dojo_test_case import DojoTestCase
from .test_permissions_audit import LegacyAuthMirrorMixin

PASSWORD = "testTEST1234!@#$"


class TestFKReassignmentAuthorization(LegacyAuthMirrorMixin, DojoTestCase):

    """
    A user with Owner on a source product, Owner on a separate destination
    Product_Type, and no membership on the source's Product_Type. The
    legacy authorization layer should treat the source's parent FK and
    any sibling FKs in mutation payloads symmetrically with CREATE:
    destination perm required, source perm not sufficient.
    """

    @classmethod
    def setUpTestData(cls):
        cls.owner_role = Role.objects.get(name="Owner")

        # Three Product Types.
        # - pt_src: user has no PT membership; member only on its product.
        # - pt_dst: user is Owner; used for the "allowed move" test.
        # - pt_outside: user has ZERO access; used for all "blocked" tests.
        cls.pt_src = Product_Type.objects.create(name="FK Reassign SRC PT")
        cls.pt_dst = Product_Type.objects.create(name="FK Reassign DST PT")
        cls.pt_outside = Product_Type.objects.create(name="FK Reassign OUTSIDE PT")

        cls.product_src = Product.objects.create(
            name="FK Reassign Src Product", description="src", prod_type=cls.pt_src,
        )
        cls.product_dst = Product.objects.create(
            name="FK Reassign Dst Product", description="dst", prod_type=cls.pt_dst,
        )
        cls.product_outside = Product.objects.create(
            name="FK Reassign Outside Product", description="out", prod_type=cls.pt_outside,
        )

        cls.user = Dojo_User.objects.create_user(
            username="fk_reassign_user", password=PASSWORD, is_active=True,
        )
        # Direct Owner on the src product (so they can edit it via the API).
        Product_Member.objects.create(
            product=cls.product_src, user=cls.user, role=cls.owner_role,
        )
        # Owner on the destination Product_Type (used by allowed-move test).
        Product_Type_Member.objects.create(
            product_type=cls.pt_dst, user=cls.user, role=cls.owner_role,
        )
        # NO membership on pt_outside or product_outside — those are the
        # canonical "destinations the user cannot reach."

        test_type, _ = Test_Type.objects.get_or_create(name="Manual Code Review")
        cls.engagement_src = Engagement.objects.create(
            name="FK Reassign Src Eng", product=cls.product_src,
            target_start=datetime.date(2024, 1, 1),
            target_end=datetime.date(2024, 12, 31),
        )
        cls.engagement_outside = Engagement.objects.create(
            name="FK Reassign Outside Eng", product=cls.product_outside,
            target_start=datetime.date(2024, 1, 1),
            target_end=datetime.date(2024, 12, 31),
        )
        cls.test_src = Test.objects.create(
            engagement=cls.engagement_src, test_type=test_type,
            target_start="2024-01-01T00:00:00Z",
            target_end="2024-12-31T00:00:00Z",
        )
        cls.test_outside = Test.objects.create(
            engagement=cls.engagement_outside, test_type=test_type,
            target_start="2024-01-01T00:00:00Z",
            target_end="2024-12-31T00:00:00Z",
        )
        cls.finding_src = Finding.objects.create(
            title="FK Reassign Src Finding", test=cls.test_src,
            severity="High", numerical_severity="S1", reporter=cls.user,
        )
        cls.finding_outside = Finding.objects.create(
            title="FK Reassign Outside Finding", test=cls.test_outside,
            severity="High", numerical_severity="S1", reporter=cls.user,
        )

        # Sibling FKs used in POST cross-tenant linking tests. Owned variant
        # lives in product_src (user has Owner); outside variant lives
        # in product_outside (user has zero access).
        tool_type, _ = Tool_Type.objects.get_or_create(name="FK Reassign Tool Type")
        tool_config = Tool_Configuration.objects.create(
            name="FK Reassign Tool Config", tool_type=tool_type,
        )
        cls.scan_config_owned = Product_API_Scan_Configuration.objects.create(
            product=cls.product_src, tool_configuration=tool_config,
        )
        cls.scan_config_outside = Product_API_Scan_Configuration.objects.create(
            product=cls.product_outside, tool_configuration=tool_config,
        )

        cls.token = Token.objects.create(user=cls.user)

    def _client(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {self.token.key}")
        return client

    def _assert_rejected(self, response):
        # Destination-perm denials come from the permission class as 403;
        # a few endpoints surface the same condition as a 400 from
        # serializer-level validation.
        self.assertIn(
            response.status_code, [400, 403],
            msg=f"Expected 400/403, got {response.status_code}: {response.content[:500]!r}",
        )

    # ────────────────────────────────────────────────────────────────────
    # Reported bug: ProductSerializer.prod_type
    # ────────────────────────────────────────────────────────────────────
    def test_product_prod_type_reassignment_to_unauthorized_pt_is_blocked(self):
        """PATCH the prod_type to a Product Type the user has no membership on."""
        r = self._client().patch(
            reverse("product-detail", args=(self.product_src.id,)),
            {"prod_type": self.pt_outside.id},
            format="json",
        )
        self._assert_rejected(r)
        self.product_src.refresh_from_db()
        self.assertEqual(self.product_src.prod_type_id, self.pt_src.id)

    def test_product_prod_type_reassignment_to_owned_pt_is_allowed(self):
        """User can move a product they own into a PT they own."""
        r = self._client().patch(
            reverse("product-detail", args=(self.product_src.id,)),
            {"prod_type": self.pt_dst.id},
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.content[:500])
        self.product_src.refresh_from_db()
        self.assertEqual(self.product_src.prod_type_id, self.pt_dst.id)

    def test_product_prod_type_noop_replay_is_allowed(self):
        """No-op PATCH (same prod_type) must not require add perm on it."""
        r = self._client().patch(
            reverse("product-detail", args=(self.product_src.id,)),
            {"prod_type": self.product_src.prod_type_id},
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.content[:500])

    # ────────────────────────────────────────────────────────────────────
    # EngagementSerializer.product (pre-existing guard, now via helper)
    # ────────────────────────────────────────────────────────────────────
    def test_engagement_product_reassignment_to_unauthorized_product_blocked(self):
        r = self._client().patch(
            reverse("engagement-detail", args=(self.engagement_src.id,)),
            {"product": self.product_outside.id},
            format="json",
        )
        self._assert_rejected(r)
        self.engagement_src.refresh_from_db()
        self.assertEqual(self.engagement_src.product_id, self.product_src.id)

    # ────────────────────────────────────────────────────────────────────
    # AppAnalysisSerializer.product
    # ────────────────────────────────────────────────────────────────────
    def test_app_analysis_product_reassignment_blocked(self):
        analysis = App_Analysis.objects.create(
            product=self.product_src, name="thing", user=self.user,
        )
        r = self._client().patch(
            reverse("app_analysis-detail", args=(analysis.id,)),
            {"product": self.product_outside.id},
            format="json",
        )
        self._assert_rejected(r)
        analysis.refresh_from_db()
        self.assertEqual(analysis.product_id, self.product_src.id)

    # ────────────────────────────────────────────────────────────────────
    # ToolProductSettingsSerializer.product
    # ────────────────────────────────────────────────────────────────────
    def test_tool_product_settings_product_reassignment_blocked(self):
        tool_type, _ = Tool_Type.objects.get_or_create(name="FK Reassign Tool Type")
        tool_config = Tool_Configuration.objects.create(
            name="FK Reassign Tool Config", tool_type=tool_type,
        )
        setting = Tool_Product_Settings.objects.create(
            name="FK Reassign Setting", product=self.product_src,
            tool_configuration=tool_config,
        )
        r = self._client().patch(
            reverse("tool_product_settings-detail", args=(setting.id,)),
            {"product": self.product_outside.id},
            format="json",
        )
        self._assert_rejected(r)
        setting.refresh_from_db()
        self.assertEqual(setting.product_id, self.product_src.id)

    # ────────────────────────────────────────────────────────────────────
    # LanguageSerializer.product
    # ────────────────────────────────────────────────────────────────────
    def test_language_product_reassignment_blocked(self):
        lang_type, _ = Language_Type.objects.get_or_create(language="Python")
        lang = Languages.objects.create(
            language=lang_type, product=self.product_src, user=self.user,
        )
        r = self._client().patch(
            reverse("languages-detail", args=(lang.id,)),
            {"product": self.product_outside.id},
            format="json",
        )
        self._assert_rejected(r)
        lang.refresh_from_db()
        self.assertEqual(lang.product_id, self.product_src.id)

    # ────────────────────────────────────────────────────────────────────
    # ProductAPIScanConfigurationSerializer.product
    # ────────────────────────────────────────────────────────────────────
    def test_product_api_scan_configuration_product_reassignment_blocked(self):
        tool_type, _ = Tool_Type.objects.get_or_create(name="FK Reassign API Scan Tool Type")
        tool_config = Tool_Configuration.objects.create(
            name="FK Reassign API Scan Tool Config", tool_type=tool_type,
        )
        scan_config = Product_API_Scan_Configuration.objects.create(
            product=self.product_src, tool_configuration=tool_config,
        )
        r = self._client().patch(
            reverse("product_api_scan_configuration-detail", args=(scan_config.id,)),
            {"product": self.product_outside.id},
            format="json",
        )
        self._assert_rejected(r)
        scan_config.refresh_from_db()
        self.assertEqual(scan_config.product_id, self.product_src.id)

    # ────────────────────────────────────────────────────────────────────
    # EngagementPresetsSerializer.product
    # ────────────────────────────────────────────────────────────────────
    def test_engagement_preset_product_reassignment_blocked(self):
        preset = Engagement_Presets.objects.create(
            title="FK Reassign Preset", product=self.product_src, scope="x",
        )
        r = self._client().patch(
            reverse("engagement_presets-detail", args=(preset.id,)),
            {"product": self.product_outside.id},
            format="json",
        )
        self._assert_rejected(r)
        preset.refresh_from_db()
        self.assertEqual(preset.product_id, self.product_src.id)

    # ────────────────────────────────────────────────────────────────────
    # BurpRawRequestResponseMultiSerializer.finding
    # ────────────────────────────────────────────────────────────────────
    def test_burp_request_response_finding_reassignment_blocked(self):
        b64 = base64.b64encode(b"GET / HTTP/1.1").decode("utf-8")
        burp = BurpRawRequestResponse.objects.create(
            finding=self.finding_src,
            burpRequestBase64=b64.encode("utf-8"),
            burpResponseBase64=b64.encode("utf-8"),
        )
        r = self._client().patch(
            reverse("request_response_pairs-detail", args=(burp.id,)),
            {
                "finding": self.finding_outside.id,
                "burpRequestBase64": b64,
                "burpResponseBase64": b64,
            },
            format="json",
        )
        self._assert_rejected(r)
        burp.refresh_from_db()
        self.assertEqual(burp.finding_id, self.finding_src.id)

    # ────────────────────────────────────────────────────────────────────
    # EndpointStatusSerializer.finding / .endpoint (V2 only — V3 deprecates
    # Endpoint in favor of Location).
    # ────────────────────────────────────────────────────────────────────
    def test_endpoint_status_finding_reassignment_blocked(self):
        if settings.V3_FEATURE_LOCATIONS:
            self.skipTest("Endpoint deprecated under V3_FEATURE_LOCATIONS")
        endpoint_src = Endpoint.objects.create(host="src.example", product=self.product_src)
        endpoint_outside = Endpoint.objects.create(host="out.example", product=self.product_outside)
        status_obj = Endpoint_Status.objects.create(
            endpoint=endpoint_src, finding=self.finding_src,
        )
        r = self._client().patch(
            reverse("endpoint_status-detail", args=(status_obj.id,)),
            {"finding": self.finding_outside.id},
            format="json",
        )
        self._assert_rejected(r)
        r2 = self._client().patch(
            reverse("endpoint_status-detail", args=(status_obj.id,)),
            {"endpoint": endpoint_outside.id},
            format="json",
        )
        self._assert_rejected(r2)
        status_obj.refresh_from_db()
        self.assertEqual(status_obj.finding_id, self.finding_src.id)
        self.assertEqual(status_obj.endpoint_id, endpoint_src.id)

    # ────────────────────────────────────────────────────────────────────
    # JIRAProjectSerializer.product / .engagement
    # ────────────────────────────────────────────────────────────────────
    def test_jira_project_product_reassignment_blocked(self):
        jira_instance = JIRA_Instance.objects.create(
            configuration_name="FK Reassign JIRA",
            url="https://jira.example",
            username="u",
            password="p",  # noqa: S106
            default_issue_type="Bug",
            epic_name_id=10000,
            open_status_key=1,
            close_status_key=2,
            info_mapping_severity="Low",
            low_mapping_severity="Low",
            medium_mapping_severity="Medium",
            high_mapping_severity="High",
            critical_mapping_severity="Critical",
        )
        project = JIRA_Project.objects.create(
            jira_instance=jira_instance,
            project_key="SRC", product=self.product_src,
        )
        r = self._client().patch(
            reverse("jira_project-detail", args=(project.id,)),
            {"product": self.product_outside.id},
            format="json",
        )
        self._assert_rejected(r)
        project.refresh_from_db()
        self.assertEqual(project.product_id, self.product_src.id)

    # ────────────────────────────────────────────────────────────────────
    # JIRAIssueSerializer.engagement / .finding / .finding_group
    # ────────────────────────────────────────────────────────────────────
    def test_jira_issue_finding_reassignment_blocked(self):
        issue = JIRA_Issue.objects.create(
            jira_id="SRC-1", jira_key="SRC-1", finding=self.finding_src,
        )
        r = self._client().patch(
            reverse("jira_issue-detail", args=(issue.id,)),
            {"finding": self.finding_outside.id},
            format="json",
        )
        self._assert_rejected(r)
        issue.refresh_from_db()
        self.assertEqual(issue.finding_id, self.finding_src.id)

    # ────────────────────────────────────────────────────────────────────
    # POST cross-tenant linking: TestCreateSerializer.api_scan_configuration
    # (UserHasTestPermission validates engagement; api_scan_configuration
    # is mass-assignable and points at another product's tool config.)
    # ────────────────────────────────────────────────────────────────────
    def test_test_create_with_unauthorized_api_scan_config_blocked(self):
        """POST test under own engagement, linking a scan config from another tenant."""
        test_type = Test_Type.objects.get(name="Manual Code Review")
        r = self._client().post(
            reverse("test-list"),
            {
                "engagement": self.engagement_src.id,
                "api_scan_configuration": self.scan_config_outside.id,
                "test_type": test_type.id,
                "target_start": "2024-01-01T00:00:00Z",
                "target_end": "2024-12-31T00:00:00Z",
            },
            format="json",
        )
        self._assert_rejected(r)
        self.assertFalse(
            Test.objects.filter(
                engagement=self.engagement_src,
                api_scan_configuration=self.scan_config_outside,
            ).exists(),
        )

    def test_test_create_with_owned_api_scan_config_allowed(self):
        """Same shape but the scan config is in the user's own product."""
        test_type = Test_Type.objects.get(name="Manual Code Review")
        r = self._client().post(
            reverse("test-list"),
            {
                "engagement": self.engagement_src.id,
                "api_scan_configuration": self.scan_config_owned.id,
                "test_type": test_type.id,
                "target_start": "2024-01-01T00:00:00Z",
                "target_end": "2024-12-31T00:00:00Z",
            },
            format="json",
        )
        self.assertEqual(r.status_code, 201, r.content[:500])

    def test_test_patch_api_scan_config_to_unauthorized_blocked(self):
        """PATCH an existing test to attach a scan config from another tenant."""
        r = self._client().patch(
            reverse("test-detail", args=(self.test_src.id,)),
            {"api_scan_configuration": self.scan_config_outside.id},
            format="json",
        )
        self._assert_rejected(r)
        self.test_src.refresh_from_db()
        self.assertIsNone(self.test_src.api_scan_configuration_id)
