import logging
from django.test import TestCase
from dojo.api_v2.long_risk_acceptance.models import (
    RiskAcceptanceEngagement,
    RiskAcceptanceEngagementEconomicImpact,
)
from dojo.api_v2.long_risk_acceptance.views import RiskAcceptanceEngagementFilter
from dojo.models import GeneralSettings, Product, Dojo_User
from django.utils import timezone
from datetime import timedelta

logger = logging.getLogger(__name__)


class TestRiskAcceptanceEngagementFilterNormalization(TestCase):
    """Test the _normalize_value method"""

    def test_normalize_value_with_brackets(self):
        """Test normalization of value with brackets"""
        filter_obj = RiskAcceptanceEngagementFilter()
        result = filter_obj._normalize_value("['lider_evc_tecnico']")
        self.assertEqual(result, "lider_evc_tecnico")

    def test_normalize_value_with_quotes(self):
        """Test normalization of value with quotes"""
        filter_obj = RiskAcceptanceEngagementFilter()
        result = filter_obj._normalize_value("'lider_evc_tecnico'")
        self.assertEqual(result, "lider_evc_tecnico")

    def test_normalize_value_with_double_quotes(self):
        """Test normalization of value with double quotes"""
        filter_obj = RiskAcceptanceEngagementFilter()
        result = filter_obj._normalize_value('"lider_evc_tecnico"')
        self.assertEqual(result, "lider_evc_tecnico")

    def test_normalize_value_with_nested_brackets(self):
        """Test normalization of nested brackets"""
        filter_obj = RiskAcceptanceEngagementFilter()
        result = filter_obj._normalize_value("[['lider_evc_tecnico']]")
        self.assertEqual(result, "lider_evc_tecnico")

    def test_normalize_value_with_spaces(self):
        """Test normalization with spaces"""
        filter_obj = RiskAcceptanceEngagementFilter()
        result = filter_obj._normalize_value("  lider_evc_tecnico  ")
        self.assertEqual(result, "lider_evc_tecnico")

    def test_normalize_value_none(self):
        """Test normalization with None"""
        filter_obj = RiskAcceptanceEngagementFilter()
        result = filter_obj._normalize_value(None)
        self.assertIsNone(result)

    def test_normalize_value_empty_string(self):
        """Test normalization with empty string"""
        filter_obj = RiskAcceptanceEngagementFilter()
        result = filter_obj._normalize_value("")
        self.assertEqual(result, "")


class TestRiskAcceptanceEngagementEconomicImpact(TestCase):
    """Test economic_impact property behavior"""
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.admin_user, _ = Dojo_User.objects.get_or_create(username="admin")
        GeneralSettings.objects.get_or_create(
            name_key="RULE_RISK_LEVEL",
            defaults={
                "value": "{'TOLERABLE': 1500, 'MODERATE': 2, 'CRITICAL': 3700, 'VERY CRITICAL': 8800}",
                "data_type": "DICT",
                "description": "Risk level thresholds",
                "status": True,
            },
        )
        self.product = Product.objects.first() or Product.objects.create(
            name="Test Product",
            prod_type_id=1,
            sla_configuration_id=1,
        )

    def test_economic_impact_returns_zero_for_unsaved_instance(self):
        ra = RiskAcceptanceEngagement()
        self.assertEqual(ra.economic_impact, 0)

    def test_economic_impact_sums_related_impact_entries(self):
        ra = RiskAcceptanceEngagement.objects.create(
            owner=self.admin_user,
            product=self.product,
            description="Test engagement",
            risk_status="Risks Pending",
            expiration_date=timezone.now() + timedelta(days=30),
        )

        RiskAcceptanceEngagementEconomicImpact.objects.create(
            risk_acceptance_engagement=ra,
            economic_impact=150,
        )
        RiskAcceptanceEngagementEconomicImpact.objects.create(
            risk_acceptance_engagement=ra,
            economic_impact=200,
        )

        self.assertEqual(ra.economic_impact, 350)


class TestRiskAcceptanceEngagementFilterOwner(TestCase):
    """Test filter_owner method"""
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.filter_obj = RiskAcceptanceEngagementFilter()
        
    def test_filter_owner_by_username(self):
        """Test filtering by owner username"""
        admin_user = Dojo_User.objects.get(username="admin")
        product = Product.objects.first()
        
        # Create test risk acceptance engagement
        ra = RiskAcceptanceEngagement.objects.create(
            owner=admin_user,
            product=product,
            description="Test engagement",
            risk_status="Risks Pending",
            expiration_date=timezone.now() + timedelta(days=30),
            reviewed_by="reviewer_user"
        )
        
        queryset = RiskAcceptanceEngagement.objects.all()
        filtered_qs = self.filter_obj.filter_owner(queryset, "owner", "admin")
        
        self.assertEqual(filtered_qs.count(), 1)
        self.assertEqual(filtered_qs.first().id, ra.id)

    def test_filter_owner_case_insensitive(self):
        """Test filtering is case insensitive"""
        admin_user = Dojo_User.objects.get(username="admin")
        product = Product.objects.first()
        
        ra = RiskAcceptanceEngagement.objects.create(
            owner=admin_user,
            product=product,
            description="Test engagement",
            risk_status="Risks Pending",
            expiration_date=timezone.now() + timedelta(days=30),
            reviewed_by="reviewer_user"
        )
        
        queryset = RiskAcceptanceEngagement.objects.all()
        filtered_qs = self.filter_obj.filter_owner(queryset, "owner", "ADMIN")
        
        self.assertEqual(filtered_qs.count(), 1)

    def test_filter_owner_with_normalized_value(self):
        """Test filtering owner with normalized value containing brackets"""
        admin_user = Dojo_User.objects.get(username="admin")
        product = Product.objects.first()
        
        ra = RiskAcceptanceEngagement.objects.create(
            owner=admin_user,
            product=product,
            description="Test engagement",
            risk_status="Risks Pending",
            expiration_date=timezone.now() + timedelta(days=30),
            reviewed_by="reviewer_user"
        )
        
        queryset = RiskAcceptanceEngagement.objects.all()
        filtered_qs = self.filter_obj.filter_owner(queryset, "owner", "['admin']")
        
        self.assertEqual(filtered_qs.count(), 1)

    def test_filter_owner_empty_value(self):
        """Test filtering with empty value returns all"""
        admin_user = Dojo_User.objects.get(username="admin")
        product = Product.objects.first()
        
        RiskAcceptanceEngagement.objects.create(
            owner=admin_user,
            product=product,
            description="Test engagement",
            risk_status="Risks Pending",
            expiration_date=timezone.now() + timedelta(days=30),
            reviewed_by="reviewer_user"
        )
        
        queryset = RiskAcceptanceEngagement.objects.all()
        initial_count = queryset.count()
        
        filtered_qs = self.filter_obj.filter_owner(queryset, "owner", "")
        
        self.assertEqual(filtered_qs.count(), initial_count)


class TestRiskAcceptanceEngagementFilterAcceptedBy(TestCase):
    """Test filter_accepted_by method"""
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.filter_obj = RiskAcceptanceEngagementFilter()
        self.admin_user = Dojo_User.objects.get(username="admin")
        self.product = Product.objects.first()

    def test_filter_accepted_by_string(self):
        """Test filtering by accepted_by string"""
        ra = RiskAcceptanceEngagement.objects.create(
            owner=self.admin_user,
            product=self.product,
            description="Test engagement",
            risk_status="Risks Pending",
            expiration_date=timezone.now() + timedelta(days=30),
            reviewed_by="reviewer_user",
            accepted_by="lider_evc_tecnico"
        )
        
        queryset = RiskAcceptanceEngagement.objects.all()
        filtered_qs = self.filter_obj.filter_accepted_by(queryset, "accepted_by", "lider_evc_tecnico")
        
        self.assertEqual(filtered_qs.count(), 1)
        self.assertEqual(filtered_qs.first().id, ra.id)

    def test_filter_accepted_by_normalized_list(self):
        """Test filtering accepted_by with normalized list format"""
        ra = RiskAcceptanceEngagement.objects.create(
            owner=self.admin_user,
            product=self.product,
            description="Test engagement",
            risk_status="Risks Pending",
            expiration_date=timezone.now() + timedelta(days=30),
            reviewed_by="reviewer_user",
            accepted_by="lider_evc_tecnico"
        )
        
        queryset = RiskAcceptanceEngagement.objects.all()
        filtered_qs = self.filter_obj.filter_accepted_by(queryset, "accepted_by", "['lider_evc_tecnico']")
        
        self.assertEqual(filtered_qs.count(), 1)

    def test_filter_accepted_by_partial_match(self):
        """Test filtering with partial match"""
        ra = RiskAcceptanceEngagement.objects.create(
            owner=self.admin_user,
            product=self.product,
            description="Test engagement",
            risk_status="Risks Pending",
            expiration_date=timezone.now() + timedelta(days=30),
            reviewed_by="reviewer_user",
            accepted_by="lider_evc_tecnico"
        )
        
        queryset = RiskAcceptanceEngagement.objects.all()
        filtered_qs = self.filter_obj.filter_accepted_by(queryset, "accepted_by", "lider")
        
        self.assertEqual(filtered_qs.count(), 1)

    def test_filter_accepted_by_empty_value(self):
        """Test filtering with empty value returns all"""
        RiskAcceptanceEngagement.objects.create(
            owner=self.admin_user,
            product=self.product,
            description="Test engagement",
            risk_status="Risks Pending",
            expiration_date=timezone.now() + timedelta(days=30),
            reviewed_by="reviewer_user",
            accepted_by="lider_evc_tecnico"
        )
        
        queryset = RiskAcceptanceEngagement.objects.all()
        initial_count = queryset.count()
        
        filtered_qs = self.filter_obj.filter_accepted_by(queryset, "accepted_by", "")
        
        self.assertEqual(filtered_qs.count(), initial_count)


class TestRiskAcceptanceEngagementFilterReviewedBy(TestCase):
    """Test filter_reviewed_by method"""
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.filter_obj = RiskAcceptanceEngagementFilter()
        self.admin_user = Dojo_User.objects.get(username="admin")
        self.product = Product.objects.first()

    def test_filter_reviewed_by_string(self):
        """Test filtering by reviewed_by string"""
        ra = RiskAcceptanceEngagement.objects.create(
            owner=self.admin_user,
            product=self.product,
            description="Test engagement",
            risk_status="Risks Pending",
            expiration_date=timezone.now() + timedelta(days=30),
            reviewed_by="reviewer_evc"
        )
        
        queryset = RiskAcceptanceEngagement.objects.all()
        filtered_qs = self.filter_obj.filter_reviewed_by(queryset, "reviewed_by", "reviewer_evc")
        
        self.assertEqual(filtered_qs.count(), 1)
        self.assertEqual(filtered_qs.first().id, ra.id)

    def test_filter_reviewed_by_normalized_list(self):
        """Test filtering reviewed_by with normalized list format"""
        ra = RiskAcceptanceEngagement.objects.create(
            owner=self.admin_user,
            product=self.product,
            description="Test engagement",
            risk_status="Risks Pending",
            expiration_date=timezone.now() + timedelta(days=30),
            reviewed_by="reviewer_evc"
        )
        
        queryset = RiskAcceptanceEngagement.objects.all()
        filtered_qs = self.filter_obj.filter_reviewed_by(queryset, "reviewed_by", "['reviewer_evc']")
        
        self.assertEqual(filtered_qs.count(), 1)

    def test_filter_reviewed_by_partial_match(self):
        """Test filtering with partial match"""
        ra = RiskAcceptanceEngagement.objects.create(
            owner=self.admin_user,
            product=self.product,
            description="Test engagement",
            risk_status="Risks Pending",
            expiration_date=timezone.now() + timedelta(days=30),
            reviewed_by="reviewer_evc"
        )
        
        queryset = RiskAcceptanceEngagement.objects.all()
        filtered_qs = self.filter_obj.filter_reviewed_by(queryset, "reviewed_by", "reviewer")
        
        self.assertEqual(filtered_qs.count(), 1)


class TestRiskAcceptanceEngagementFilterIntegration(TestCase):
    """Integration tests for the complete filterset"""
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.admin_user = Dojo_User.objects.get(username="admin")
        self.product = Product.objects.first()
        
        # Create multiple test records
        self.ra1 = RiskAcceptanceEngagement.objects.create(
            owner=self.admin_user,
            product=self.product,
            description="Test engagement 1",
            risk_status="Risks Active",
            expiration_date=timezone.now() + timedelta(days=30),
            reviewed_by="reviewer1",
            accepted_by="accepter1"
        )
        
        self.ra2 = RiskAcceptanceEngagement.objects.create(
            owner=self.admin_user,
            product=self.product,
            description="Test engagement 2",
            risk_status="Risks Accepted",
            expiration_date=timezone.now() + timedelta(days=60),
            reviewed_by="reviewer2",
            accepted_by="accepter2"
        )

    def test_filterset_initialization(self):
        """Test that filterset can be initialized"""
        filterset = RiskAcceptanceEngagementFilter()
        self.assertIsNotNone(filterset)

    def test_filterset_with_queryset(self):
        """Test filterset with queryset"""
        data = {}
        filterset = RiskAcceptanceEngagementFilter(data, queryset=RiskAcceptanceEngagement.objects.all())
        self.assertEqual(filterset.qs.count(), 2)

    def test_filterset_filter_by_owner(self):
        """Test filterset filtering by owner"""
        data = {"owner": "admin"}
        filterset = RiskAcceptanceEngagementFilter(data, queryset=RiskAcceptanceEngagement.objects.all())
        self.assertEqual(filterset.qs.count(), 2)

    def test_filterset_filter_by_risk_status(self):
        """Test filterset filtering by risk_status"""
        data = {"risk_status": "Risks Active"}
        filterset = RiskAcceptanceEngagementFilter(data, queryset=RiskAcceptanceEngagement.objects.all())
        self.assertEqual(filterset.qs.count(), 1)

    def test_filterset_filter_multiple_fields(self):
        """Test filterset filtering by multiple fields"""
        data = {
            "risk_status": "Risks Active",
            "reviewed_by": "reviewer1"
        }
        filterset = RiskAcceptanceEngagementFilter(data, queryset=RiskAcceptanceEngagement.objects.all())
        self.assertEqual(filterset.qs.count(), 1)
