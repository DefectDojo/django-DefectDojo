import collections
import decimal
import logging
import warnings
from datetime import datetime, timedelta

import six
import tagulous
from auditlog.models import LogEntry
from django import forms
from django.apps import apps
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db.models import Count, JSONField, Q
from django.forms import HiddenInput
from django.utils.timezone import now, tzinfo
from django.utils.translation import gettext_lazy as _
from django_filters import (
    BooleanFilter,
    CharFilter,
    DateFilter,
    DateFromToRangeFilter,
    DateTimeFilter,
    FilterSet,
    ModelChoiceFilter,
    ModelMultipleChoiceFilter,
    MultipleChoiceFilter,
    NumberFilter,
    OrderingFilter,
    RangeFilter,
)
from django_filters import rest_framework as filters
from django_filters.filters import ChoiceFilter, _truncate
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from polymorphic.base import ManagerInheritanceWarning

# from tagulous.forms import TagWidget
# import tagulous
from dojo.authorization.roles_permissions import Permissions
from dojo.endpoint.queries import get_authorized_endpoints
from dojo.engagement.queries import get_authorized_engagements
from dojo.finding.helper import (
    ACCEPTED_FINDINGS_QUERY,
    CLOSED_FINDINGS_QUERY,
    FALSE_POSITIVE_FINDINGS_QUERY,
    INACTIVE_FINDINGS_QUERY,
    NOT_ACCEPTED_FINDINGS_QUERY,
    OPEN_FINDINGS_QUERY,
    OUT_OF_SCOPE_FINDINGS_QUERY,
    UNDER_REVIEW_QUERY,
    VERIFIED_FINDINGS_QUERY,
    WAS_ACCEPTED_FINDINGS_QUERY,
)
from dojo.finding.queries import get_authorized_findings
from dojo.finding_group.queries import get_authorized_finding_groups
from dojo.models import (
    EFFORT_FOR_FIXING_CHOICES,
    ENGAGEMENT_STATUS_CHOICES,
    IMPORT_ACTIONS,
    SEVERITY_CHOICES,
    App_Analysis,
    ChoiceQuestion,
    Cred_Mapping,
    Development_Environment,
    Dojo_Group,
    Dojo_User,
    DojoMeta,
    Endpoint,
    Endpoint_Status,
    Engagement,
    Engagement_Survey,
    Finding,
    Finding_Group,
    Finding_Template,
    Note_Type,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Question,
    Risk_Acceptance,
    Test,
    Test_Import,
    Test_Import_Finding_Action,
    Test_Type,
    TextQuestion,
    User,
    Vulnerability_Id,
)
from dojo.location.models import Location
from dojo.product.queries import get_authorized_products
from dojo.product_type.queries import get_authorized_product_types
from dojo.risk_acceptance.queries import get_authorized_risk_acceptances
from dojo.test.queries import get_authorized_tests
from dojo.user.queries import get_authorized_users
from dojo.utils import get_system_setting, is_finding_groups_enabled
from dojo.api_helpers.filters import StaticMethodFilters
from dojo.location.status import FindingLocationStatus, ProductLocationStatus

logger = logging.getLogger(__name__)

BOOLEAN_CHOICES = (("false", "No"), ("true", "Yes"))
EARLIEST_FINDING = None



class URLFilter(StaticMethodFilters):
    StaticMethodFilters.create_char_filters("url__protocol", "Protocol", locals())
    StaticMethodFilters.create_char_filters("url__user_info", "User Info", locals())
    StaticMethodFilters.create_char_filters("url__host", "Host", locals())
    StaticMethodFilters.create_char_filters("url__path", "Path", locals())
    StaticMethodFilters.create_integer_filters("url__port", "Port", locals())
    StaticMethodFilters.create_char_filters("url__query", "Query Parameters", locals())
    StaticMethodFilters.create_char_filters("url__fragment", "Fragment", locals())
    StaticMethodFilters.create_integer_filters("products__product__id", "Product ID", locals())
    StaticMethodFilters.create_choice_filters("products__status", "Product Status", ProductLocationStatus.choices, locals())
    StaticMethodFilters.create_choice_filters("findings__status", "Finding Status", FindingLocationStatus.choices, locals())
    StaticMethodFilters.create_char_filters("products__product__name", "Product Name", locals())
    StaticMethodFilters.create_char_filters("products__product__tags__name", "Product Tags", locals())
    StaticMethodFilters.create_char_filters("findings__finding__tags__name", "Finding Tags", locals())
    product = NumberFilter(field_name="products__product", widget=HiddenInput())
    StaticMethodFilters.create_ordering_filters(
        locals(),
        (
            "id",
            "url__protocol",
            "url__host",
            "url__user_info",
            "url__path",
            "url__port",
            "url__query",
            "url__fragment",
            "created_at",
            "updated_at",
        ),
    )

    def __init__(self, *args, **kwargs):
        self.user = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)

    @property
    def qs(self):
        parent = super().qs
        return get_authorized_endpoints(Permissions.Location_View, parent)
