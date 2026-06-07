import collections
import decimal
import logging
import warnings
from datetime import datetime, timedelta

import six
import tagulous
from django.apps import apps
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db.models import Count, Q
from django.forms import HiddenInput
from django.utils.timezone import now, tzinfo
from django.utils.translation import gettext_lazy as _
from django_filters import (
    BooleanFilter,
    CharFilter,
    DateFilter,
    DateTimeFilter,
    FilterSet,
    ModelMultipleChoiceFilter,
    MultipleChoiceFilter,
    NumberFilter,
    OrderingFilter,
    RangeFilter,
)
from django_filters import rest_framework as filters
from django_filters.filters import ChoiceFilter
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from polymorphic.base import ManagerInheritanceWarning

# from tagulous.forms import TagWidget
# import tagulous
from dojo.endpoint.queries import get_authorized_endpoints_for_queryset
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
from dojo.labels import get_labels
from dojo.models import (
    SEVERITY_CHOICES,
    App_Analysis,
    ChoiceQuestion,
    Development_Environment,
    Dojo_User,
    DojoMeta,
    Endpoint,
    Endpoint_Status,
    Engagement,
    Engagement_Survey,
    Finding,
    Finding_Template,
    Note_Type,
    Product,
    Product_Type,
    Question,
    Risk_Acceptance,
    Test,
    TextQuestion,
    User,
    Vulnerability_Id,
)
from dojo.product.queries import get_authorized_products
from dojo.product_type.queries import get_authorized_product_types
from dojo.utils import get_system_setting, is_finding_groups_enabled, truncate_timezone_aware

logger = logging.getLogger(__name__)

labels = get_labels()

BOOLEAN_CHOICES = (("false", "No"), ("true", "Yes"))
EARLIEST_FINDING = None


def custom_filter(queryset, name, value):
    values = value.split(",")
    cust_filter = (f"{name}__in")
    return queryset.filter(Q(**{cust_filter: values}))


def custom_vulnerability_id_filter(queryset, name, value):
    values = value.split(",")
    ids = Vulnerability_Id.objects \
        .filter(vulnerability_id__in=values) \
        .values_list("finding_id", flat=True)
    return queryset.filter(id__in=ids)


def vulnerability_id_filter(queryset, name, value):
    ids = Vulnerability_Id.objects \
        .filter(vulnerability_id=value) \
        .values_list("finding_id", flat=True)
    return queryset.filter(id__in=ids)


class NumberInFilter(filters.BaseInFilter, filters.NumberFilter):
    pass


class CharFieldInFilter(filters.BaseInFilter, filters.CharFilter):
    def __init__(self, *args, **kwargs):
        super(CharFilter, self).__init__(*args, **kwargs)


class CharFieldFilterANDExpression(CharFieldInFilter):
    def filter(self, queryset, value):
        # Catch the case where a value if not supplied
        if not value:
            return queryset
        # Do the filtering
        objects = set(value.split(","))
        return (
            queryset.filter(**{f"{self.field_name}__in": objects})
            .annotate(object_count=Count(self.field_name))
            .filter(object_count=len(objects))
        )


class FindingStatusFilter(ChoiceFilter):
    def any(self, qs, name):
        return qs

    def open(self, qs, name):
        return qs.filter(OPEN_FINDINGS_QUERY)

    def verified(self, qs, name):
        return qs.filter(VERIFIED_FINDINGS_QUERY)

    def out_of_scope(self, qs, name):
        return qs.filter(OUT_OF_SCOPE_FINDINGS_QUERY)

    def false_positive(self, qs, name):
        return qs.filter(FALSE_POSITIVE_FINDINGS_QUERY)

    def inactive(self, qs, name):
        return qs.filter(INACTIVE_FINDINGS_QUERY)

    def risk_accepted(self, qs, name):
        return qs.filter(ACCEPTED_FINDINGS_QUERY)

    def closed(self, qs, name):
        return qs.filter(CLOSED_FINDINGS_QUERY)

    def under_review(self, qs, name):
        return qs.filter(UNDER_REVIEW_QUERY)

    options = {
        None: (_("Any"), any),
        0: (_("Open"), open),
        1: (_("Verified"), verified),
        2: (_("Out Of Scope"), out_of_scope),
        3: (_("False Positive"), false_positive),
        4: (_("Inactive"), inactive),
        5: (_("Risk Accepted"), risk_accepted),
        6: (_("Closed"), closed),
        7: (_("Under Review"), under_review),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        earliest_finding = get_earliest_finding(qs)
        if earliest_finding is not None:
            start_date = datetime.combine(
                earliest_finding.date, datetime.min.time()).replace(tzinfo=tzinfo())
            self.start_date = truncate_timezone_aware(start_date - timedelta(days=1))
            self.end_date = truncate_timezone_aware(now() + timedelta(days=1))
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](self, qs, self.field_name)


class FindingSLAFilter(ChoiceFilter):
    def any(self, qs, name):
        return qs

    def sla_satisfied(self, qs, name):
        # return findings that have an sla expiration date after today or no sla expiration date
        return qs.filter(Q(sla_expiration_date__isnull=True) | Q(sla_expiration_date__gt=now().date()))

    def sla_violated(self, qs, name):
        # return active findings that have an sla expiration date before today
        return qs.filter(
            Q(
                active=True,
                false_p=False,
                duplicate=False,
                out_of_scope=False,
                risk_accepted=False,
                is_mitigated=False,
                mitigated=None,
            ) & Q(sla_expiration_date__lt=now().date()),
        )

    options = {
        None: (_("Any"), any),
        0: (_("False"), sla_satisfied),
        1: (_("True"), sla_violated),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](self, qs, self.field_name)


class FindingHasJIRAFilter(ChoiceFilter):
    def no_jira(self, qs, name):
        return qs.filter(Q(jira_issue=None) & Q(finding_group__jira_issue=None))

    def any_jira(self, qs, name):
        return qs.filter(~Q(jira_issue=None) | ~Q(finding_group__jira_issue=None))

    def all_items(self, qs, name):
        return qs

    options = {
        0: (_("Yes"), any_jira),
        1: (_("No"), no_jira),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            return self.all_items(qs, self.field_name)

        return self.options[value][1](self, qs, self.field_name)


class ProductSLAFilter(ChoiceFilter):
    def any(self, qs, name):
        return qs

    def sla_satisifed(self, qs, name):
        for product in qs:
            if product.violates_sla():
                qs = qs.exclude(id=product.id)
        return qs

    def sla_violated(self, qs, name):
        for product in qs:
            if not product.violates_sla():
                qs = qs.exclude(id=product.id)
        return qs

    options = {
        None: (_("Any"), any),
        0: (_("False"), sla_satisifed),
        1: (_("True"), sla_violated),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](self, qs, self.field_name)


def get_earliest_finding(queryset=None):
    if queryset is None:  # don't to 'if not queryset' which will trigger the query
        queryset = Finding.objects.all()

    try:
        EARLIEST_FINDING = queryset.earliest("date")
    except (Finding.DoesNotExist, Endpoint_Status.DoesNotExist):
        EARLIEST_FINDING = None
    return EARLIEST_FINDING


def cwe_options(queryset):
    cwe = {}
    cwe = dict([cwe, cwe]
                for cwe in queryset.order_by().values_list("cwe", flat=True).distinct()
                if isinstance(cwe, int) and cwe is not None and cwe > 0)
    cwe = collections.OrderedDict(sorted(cwe.items()))
    return list(cwe.items())


class DojoFilter(FilterSet):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for field in ["tags", "test__tags", "test__engagement__tags", "test__engagement__product__tags",
                        "not_tags", "not_test__tags", "not_test__engagement__tags", "not_test__engagement__product__tags"]:
            if field in self.form.fields:
                tags_filter = self.filters["tags"]
                model = tags_filter.model

                self.form.fields[field] = model._meta.get_field("tags").formfield()
                # we defer applying the select2 autocomplete because there can be multiple forms on the same page
                # and form.js would then apply select2 multiple times, resulting in duplicated fields
                # the initialization now happens in filter_js_snippet.html
                self.form.fields[field].widget.tag_options += tagulous.models.options.TagOptions(autocomplete_settings={"width": "200px", "defer": True})
                tagged_model, exclude = get_tags_model_from_field_name(field)
                if tagged_model:  # only if not the normal tags field
                    self.form.fields[field].label = get_tags_label_from_model(tagged_model)
                    self.form.fields[field].autocomplete_tags = tagged_model.tags.tag_model.objects.all().order_by("name")

                if exclude:
                    self.form.fields[field].label = "Not " + self.form.fields[field].label

    def filter_queryset(self, queryset):
        qs = super().filter_queryset(queryset)
        if hasattr(self, "form") and hasattr(self.form, "cleaned_data"):
            for name, f in self.filters.items():
                field_name = getattr(f, "field_name", "") or ""
                # Only apply distinct for tag lookups that can duplicate base rows
                if "tags__name" in field_name:
                    value = self.form.cleaned_data.get(name, None)
                    if value not in (None, "", [], (), {}):
                        lookup_expr = getattr(f, "lookup_expr", None)
                        is_exclude = getattr(f, "exclude", False)
                        needs_distinct = (
                            is_exclude
                            or lookup_expr in {
                                "in",
                                "contains",
                                "icontains",
                                "startswith",
                                "istartswith",
                                "endswith",
                                "iendswith",
                            }
                        )
                        # exact/iexact typically won't duplicate rows
                        if needs_distinct:
                            return qs.distinct()
        return qs


def get_tags_model_from_field_name(field):
    exclude = False
    if field.startswith("not_"):
        field = field.replace("not_", "")
        exclude = True
    try:
        parts = field.split("__")
        model_name = parts[-2]
        return apps.get_model(f"dojo.{model_name}", require_ready=True), exclude
    except Exception:
        return None, exclude


def get_tags_label_from_model(model):
    if model:
        if model is Product_Type:
            return labels.ORG_FILTERS_TAGS_LABEL
        if model is Product:
            return labels.ASSET_FILTERS_TAGS_LABEL
        return f"Tags ({model.__name__.title()})"
    return "Tags (Unknown)"


def get_finding_filterset_fields(*, metrics=False, similar=False, filter_string_matching=False):
    fields = []

    if similar:
        fields.extend([
            "id",
            "hash_code",
        ])

    fields.extend(["title", "component_name", "component_version"])

    if metrics:
        fields.extend([
            "start_date",
            "end_date",
        ])

    fields.extend([
        "date",
        "cwe",
        "severity",
        "last_reviewed",
        "last_status_update",
        "mitigated",
        "reporter",
        "reviewers",
    ])

    if filter_string_matching:
        fields.extend([
            "reporter",
            "reviewers",
            "test__engagement__product__prod_type__name",
            "test__engagement__product__name",
            "test__engagement__name",
            "test__title",
        ])
    else:
        fields.extend([
            "reporter",
            "reviewers",
            "test__engagement__product__prod_type",
            "test__engagement__product",
            "test__engagement",
            "test",
        ])

    fields.extend([
        "test__test_type",
        "test__engagement__version",
        "test__version",
        "endpoints",
        "status",
        "active",
        "verified",
        "duplicate",
        "is_mitigated",
        "out_of_scope",
        "false_p",
        "has_component",
        "has_notes",
        "file_path",
        "unique_id_from_tool",
        "vuln_id_from_tool",
        "service",
        "epss_score",
        "epss_score_range",
        "epss_percentile",
        "epss_percentile_range",
        "known_exploited",
        "ransomware_used",
        "kev_date",
        "kev_before",
        "kev_after",
        "fix_available",
    ])

    if similar:
        fields.extend([
            "id",
        ])

    fields.extend([
        "param",
        "payload",
        "risk_acceptance",
    ])

    if get_system_setting("enable_jira"):
        fields.extend([
            "has_jira_issue",
            "jira_creation",
            "jira_change",
            "jira_issue__jira_key",
        ])

    if is_finding_groups_enabled():
        if filter_string_matching:
            fields.extend([
                "has_finding_group",
                "finding_group__name",
            ])
        else:
            fields.extend([
                "has_finding_group",
                "finding_group",
            ])

        if get_system_setting("enable_jira"):
            fields.extend([
                "has_jira_group_issue",
                "has_any_jira_issue",
            ])

    return fields


def filter_endpoints_base(queryset, name, value, statuses=None, host=None):
    """
    Apply `endpoints` filter, and if location_status or host
    are present, combine them on the same row.
    """
    filters_kwargs = {"locations__location": value}
    if statuses:
        filters_kwargs["locations__status__in"] = statuses
    if host:
        filters_kwargs["locations__location__url__host__icontains"] = host

    return queryset.filter(**filters_kwargs)


def filter_endpoints_host_base(queryset, name, value, statuses=None, endpoint_id=None):
    """
    Apply `endpoints__host` filter, and if endpoints or location_status
    are present, combine them on the same row.
    """
    filters_kwargs = {"locations__location__url__host__icontains": value}
    if endpoint_id:
        filters_kwargs["locations__location"] = endpoint_id
    if statuses:
        filters_kwargs["locations__status__in"] = statuses

    return queryset.filter(**filters_kwargs)


class FindingTagFilter(DojoFilter):
    tag = CharFilter(
        field_name="tags__name",
        lookup_expr="icontains",
        label="Tag name contains",
        help_text="Search for tags on a Finding that contain a given pattern")
    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Finding.tags.tag_model.objects.all().order_by("name"),
        help_text="Filter Findings by the selected tags (OR logic)",
    )

    tags_and = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Finding.tags.tag_model.objects.all().order_by("name"),
        help_text="Filter Findings by the selected tags (AND logic)",
        label="Tags (AND)",
        conjoined=True,
    )

    test__tags = ModelMultipleChoiceFilter(
        field_name="test__tags__name",
        to_field_name="name",
        queryset=Test.tags.tag_model.objects.all().order_by("name"),
        help_text="Filter Findings by the selected Test tags (OR logic)",
        label="Test Tags",
    )

    test__tags_and = ModelMultipleChoiceFilter(
        field_name="test__tags__name",
        to_field_name="name",
        queryset=Test.tags.tag_model.objects.all().order_by("name"),
        help_text="Filter Findings by the selected Test tags (AND logic)",
        label="Test Tags (AND)",
        conjoined=True,
    )

    test__engagement__tags = ModelMultipleChoiceFilter(
        field_name="test__engagement__tags__name",
        to_field_name="name",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"),
        help_text="Filter Findings by the selected Engagement tags (OR logic)",
        label="Engagement Tags",
    )

    test__engagement__tags_and = ModelMultipleChoiceFilter(
        field_name="test__engagement__tags__name",
        to_field_name="name",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"),
        help_text="Filter Findings by the selected Engagement tags (AND logic)",
        label="Engagement Tags (AND)",
        conjoined=True,
    )

    test__engagement__product__tags = ModelMultipleChoiceFilter(
        field_name="test__engagement__product__tags__name",
        to_field_name="name",
        queryset=Product.tags.tag_model.objects.all().order_by("name"),
        help_text="Filter Findings by the selected Product tags (OR logic)",
        label="Product Tags",
    )

    test__engagement__product__tags_and = ModelMultipleChoiceFilter(
        field_name="test__engagement__product__tags__name",
        to_field_name="name",
        queryset=Product.tags.tag_model.objects.all().order_by("name"),
        help_text="Filter Findings by the selected Product tags (AND logic)",
        label="Product Tags (AND)",
        conjoined=True,
    )

    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Finding.tags.tag_model.objects.all().order_by("name"),
        help_text="Search for tags on a Finding that contain a given pattern, and exclude them",
        exclude=True)
    not_test__tags = ModelMultipleChoiceFilter(
        field_name="test__tags__name",
        to_field_name="name",
        label="Test without tags",
        queryset=Test.tags.tag_model.objects.all().order_by("name"),
        help_text="Search for tags on a Test that contain a given pattern, and exclude them",
        exclude=True)
    not_test__engagement__tags = ModelMultipleChoiceFilter(
        field_name="test__engagement__tags__name",
        to_field_name="name",
        label="Engagement without tags",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"),
        help_text="Search for tags on a Engagement that contain a given pattern, and exclude them",
        exclude=True)
    not_test__engagement__product__tags = ModelMultipleChoiceFilter(
        field_name="test__engagement__product__tags__name",
        to_field_name="name",
        label=labels.ASSET_FILTERS_ASSETS_WITHOUT_TAGS_LABEL,
        queryset=Product.tags.tag_model.objects.all().order_by("name"),
        help_text=labels.ASSET_FILTERS_ASSETS_WITHOUT_TAGS_HELP,
        exclude=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class FindingTagStringFilter(FilterSet):
    tags_contains = CharFilter(
        label="Finding Tag Contains",
        field_name="tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    tags = CharFilter(
        label="Finding Tag",
        field_name="tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    test__tags_contains = CharFilter(
        label="Test Tag Contains",
        field_name="test__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    test__tags = CharFilter(
        label="Test Tag",
        field_name="test__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    test__engagement__tags_contains = CharFilter(
        label="Engagement Tag Contains",
        field_name="test__engagement__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    test__engagement__tags = CharFilter(
        label="Engagement Tag",
        field_name="test__engagement__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    test__engagement__product__tags_contains = CharFilter(
        label=labels.ASSET_FILTERS_TAG_ASSET_CONTAINS_LABEL,
        field_name="test__engagement__product__tags__name",
        lookup_expr="icontains",
        help_text=labels.ASSET_FILTERS_TAG_ASSET_CONTAINS_HELP)
    test__engagement__product__tags = CharFilter(
        label=labels.ASSET_FILTERS_TAG_ASSET_LABEL,
        field_name="test__engagement__product__tags__name",
        lookup_expr="iexact",
        help_text=labels.ASSET_FILTERS_TAG_ASSET_HELP)

    not_tags_contains = CharFilter(
        label="Finding Tag Does Not Contain",
        field_name="tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern, and exclude them",
        exclude=True)
    not_tags = CharFilter(
        label="Not Finding Tag",
        field_name="tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match, and exclude them",
        exclude=True)
    not_test__tags_contains = CharFilter(
        label="Test Tag Does Not Contain",
        field_name="test__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Test that contain a given pattern, and exclude them",
        exclude=True)
    not_test__tags = CharFilter(
        label="Not Test Tag",
        field_name="test__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Test that are an exact match, and exclude them",
        exclude=True)
    not_test__engagement__tags_contains = CharFilter(
        label="Engagement Tag Does Not Contain",
        field_name="test__engagement__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Engagement that contain a given pattern, and exclude them",
        exclude=True)
    not_test__engagement__tags = CharFilter(
        label="Not Engagement Tag",
        field_name="test__engagement__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Engagement that are an exact match, and exclude them",
        exclude=True)
    not_test__engagement__product__tags_contains = CharFilter(
        label=labels.ASSET_FILTERS_TAG_NOT_CONTAIN_LABEL,
        field_name="test__engagement__product__tags__name",
        lookup_expr="icontains",
        help_text=labels.ASSET_FILTERS_TAG_NOT_CONTAIN_HELP,
        exclude=True)
    not_test__engagement__product__tags = CharFilter(
        label=labels.ASSET_FILTERS_TAG_NOT_LABEL,
        field_name="test__engagement__product__tags__name",
        lookup_expr="iexact",
        help_text=labels.ASSET_FILTERS_TAG_NOT_HELP,
        exclude=True)

    def delete_tags_from_form(self, tag_list: list):
        for tag in tag_list:
            self.form.fields.pop(tag, None)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class DateRangeFilter(ChoiceFilter):
    options = {
        None: (_("Any date"), lambda qs, _: qs.all()),
        1: (_("Today"), lambda qs, name: qs.filter(**{
            f"{name}__year": now().year,
            f"{name}__month": now().month,
            f"{name}__day": now().day,
        })),
        2: (_("Past 7 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": truncate_timezone_aware(now() - timedelta(days=7)),
            f"{name}__lt": truncate_timezone_aware(now() + timedelta(days=1)),
        })),
        3: (_("Past 30 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": truncate_timezone_aware(now() - timedelta(days=30)),
            f"{name}__lt": truncate_timezone_aware(now() + timedelta(days=1)),
        })),
        4: (_("Past 90 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": truncate_timezone_aware(now() - timedelta(days=90)),
            f"{name}__lt": truncate_timezone_aware(now() + timedelta(days=1)),
        })),
        5: (_("Current month"), lambda qs, name: qs.filter(**{
            f"{name}__year": now().year,
            f"{name}__month": now().month,
        })),
        6: (_("Current year"), lambda qs, name: qs.filter(**{
            f"{name}__year": now().year,
        })),
        7: (_("Past year"), lambda qs, name: qs.filter(**{
            f"{name}__gte": truncate_timezone_aware(now() - timedelta(days=365)),
            f"{name}__lt": truncate_timezone_aware(now() + timedelta(days=1)),
        })),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](qs, self.field_name)


class DateRangeOmniFilter(ChoiceFilter):
    options = {
        None: (_("Any date"), lambda qs, _: qs.all()),
        1: (_("Today"), lambda qs, name: qs.filter(**{
            f"{name}__year": now().year,
            f"{name}__month": now().month,
            f"{name}__day": now().day,
        })),
        2: (_("Next 7 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": truncate_timezone_aware(now() + timedelta(days=1)),
            f"{name}__lt": truncate_timezone_aware(now() + timedelta(days=7)),
        })),
        3: (_("Next 30 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": truncate_timezone_aware(now() + timedelta(days=1)),
            f"{name}__lt": truncate_timezone_aware(now() + timedelta(days=30)),
        })),
        4: (_("Next 90 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": truncate_timezone_aware(now() + timedelta(days=1)),
            f"{name}__lt": truncate_timezone_aware(now() + timedelta(days=90)),
        })),
        5: (_("Past 7 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": truncate_timezone_aware(now() - timedelta(days=7)),
            f"{name}__lt": truncate_timezone_aware(now() + timedelta(days=1)),
        })),
        6: (_("Past 30 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": truncate_timezone_aware(now() - timedelta(days=30)),
            f"{name}__lt": truncate_timezone_aware(now() + timedelta(days=1)),
        })),
        7: (_("Past 90 days"), lambda qs, name: qs.filter(**{
            f"{name}__gte": truncate_timezone_aware(now() - timedelta(days=90)),
            f"{name}__lt": truncate_timezone_aware(now() + timedelta(days=1)),
        })),
        8: (_("Current month"), lambda qs, name: qs.filter(**{
            f"{name}__year": now().year,
            f"{name}__month": now().month,
        })),
        9: (_("Past year"), lambda qs, name: qs.filter(**{
            f"{name}__gte": truncate_timezone_aware(now() - timedelta(days=365)),
            f"{name}__lt": truncate_timezone_aware(now() + timedelta(days=1)),
        })),
        10: (_("Current year"), lambda qs, name: qs.filter(**{
            f"{name}__year": now().year,
        })),
        11: (_("Next year"), lambda qs, name: qs.filter(**{
            f"{name}__gte": truncate_timezone_aware(now() + timedelta(days=1)),
            f"{name}__lt": truncate_timezone_aware(now() + timedelta(days=365)),
        })),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](qs, self.field_name)


class ReportBooleanFilter(ChoiceFilter):
    options = {
        None: (_("Either"), lambda qs, _: qs.all()),
        1: (_("Yes"), lambda qs, name: qs.filter(**{
            f"{name}": True,
        })),
        2: (_("No"), lambda qs, name: qs.filter(**{
            f"{name}": False,
        })),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](qs, self.field_name)


class ReportRiskAcceptanceFilter(ChoiceFilter):

    def any(self, qs, name):
        return qs.all()

    def accepted(self, qs, name):
        # return qs.filter(risk_acceptance__isnull=False)
        return qs.filter(ACCEPTED_FINDINGS_QUERY)

    def not_accepted(self, qs, name):
        return qs.filter(NOT_ACCEPTED_FINDINGS_QUERY)

    def was_accepted(self, qs, name):
        return qs.filter(WAS_ACCEPTED_FINDINGS_QUERY)

    options = {
        None: (_("Either"), any),
        1: (_("Yes"), accepted),
        2: (_("No"), not_accepted),
        3: (_("Expired"), was_accepted),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](self, qs, self.field_name)


class MetricsDateRangeFilter(ChoiceFilter):
    def any(self, qs, name):
        earliest_finding = get_earliest_finding(qs)
        if earliest_finding is not None:
            start_date = datetime.combine(
                earliest_finding.date, datetime.min.time()).replace(tzinfo=tzinfo())
            self.start_date = truncate_timezone_aware(start_date - timedelta(days=1))
            self.end_date = truncate_timezone_aware(now() + timedelta(days=1))
            return qs.all()
        return None

    def current_month(self, qs, name):
        self.start_date = datetime(now().year, now().month, 1, 0, 0, 0).replace(tzinfo=tzinfo())
        self.end_date = now()
        return qs.filter(**{
            f"{name}__year": self.start_date.year,
            f"{name}__month": self.start_date.month,
        })

    def current_year(self, qs, name):
        self.start_date = datetime(now().year, 1, 1, 0, 0, 0).replace(tzinfo=tzinfo())
        self.end_date = now()
        return qs.filter(**{
            f"{name}__year": now().year,
        })

    def past_x_days(self, qs, name, days):
        self.start_date = truncate_timezone_aware(now() - timedelta(days=days))
        self.end_date = truncate_timezone_aware(now() + timedelta(days=1))
        return qs.filter(**{
            f"{name}__gte": self.start_date,
            f"{name}__lt": self.end_date,
        })

    def past_seven_days(self, qs, name):
        return self.past_x_days(qs, name, 7)

    def past_thirty_days(self, qs, name):
        return self.past_x_days(qs, name, 30)

    def past_ninety_days(self, qs, name):
        return self.past_x_days(qs, name, 90)

    def past_six_months(self, qs, name):
        return self.past_x_days(qs, name, 183)

    def past_year(self, qs, name):
        return self.past_x_days(qs, name, 365)

    options = {
        None: (_("Past 30 days"), past_thirty_days),
        1: (_("Past 7 days"), past_seven_days),
        2: (_("Past 90 days"), past_ninety_days),
        3: (_("Current month"), current_month),
        4: (_("Current year"), current_year),
        5: (_("Past 6 Months"), past_six_months),
        6: (_("Past year"), past_year),
        7: (_("Any date"), any),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        if value == 8:
            return qs
        earliest_finding = get_earliest_finding(qs)
        if earliest_finding is not None:
            start_date = datetime.combine(
                earliest_finding.date, datetime.min.time()).replace(tzinfo=tzinfo())
            self.start_date = truncate_timezone_aware(start_date - timedelta(days=1))
            self.end_date = truncate_timezone_aware(now() + timedelta(days=1))
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](self, qs, self.field_name)


class ApiDojoMetaFilter(DojoFilter):
    name_case_insensitive = CharFilter(field_name="name", lookup_expr="iexact")
    value_case_insensitive = CharFilter(field_name="value", lookup_expr="iexact")
    endpoint = NumberFilter(field_name="location__products__id", lookup_expr="exact")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # TODO: Delete this after the move to Locations
        if not settings.V3_FEATURE_LOCATIONS:
            self.filters["endpoint"] = NumberFilter(field_name="endpoint", lookup_expr="exact")

    class Meta:
        model = DojoMeta
        fields = [
            "id",
            "product",
            "endpoint",
            "location",
            "finding",
            "name",
            "value",
        ]


class PercentageRangeFilter(RangeFilter):
    def filter(self, qs, value):
        if value is not None:
            start = value.start / decimal.Decimal("100.0") if value.start else None
            stop = value.stop / decimal.Decimal("100.0") if value.stop else None
            value = slice(start, stop)
        return super().filter(qs, value)


class ApiFindingFilter(DojoFilter):
    # BooleanFilter
    active = BooleanFilter(field_name="active")
    duplicate = BooleanFilter(field_name="duplicate")
    dynamic_finding = BooleanFilter(field_name="dynamic_finding")
    false_p = BooleanFilter(field_name="false_p")
    is_mitigated = BooleanFilter(field_name="is_mitigated")
    out_of_scope = BooleanFilter(field_name="out_of_scope")
    static_finding = BooleanFilter(field_name="static_finding")
    under_defect_review = BooleanFilter(field_name="under_defect_review")
    under_review = BooleanFilter(field_name="under_review")
    verified = BooleanFilter(field_name="verified")
    has_jira = BooleanFilter(field_name="jira_issue", lookup_expr="isnull", exclude=True)
    fix_available = BooleanFilter(field_name="fix_available")
    mitigation_available = BooleanFilter(method="filter_mitigation_available", label="Mitigation Available")
    # CharFilter
    component_version = CharFilter(lookup_expr="icontains")
    component_name = CharFilter(lookup_expr="icontains")
    vulnerability_id = CharFilter(method=custom_vulnerability_id_filter)
    description = CharFilter(lookup_expr="icontains")
    file_path = CharFilter(lookup_expr="icontains")
    hash_code = CharFilter(lookup_expr="icontains")
    impact = CharFilter(lookup_expr="icontains")
    mitigation = CharFilter(lookup_expr="icontains")
    numerical_severity = CharFilter(method=custom_filter, field_name="numerical_severity")
    param = CharFilter(lookup_expr="icontains")
    payload = CharFilter(lookup_expr="icontains")
    references = CharFilter(lookup_expr="icontains")
    severity = CharFilter(method=custom_filter, field_name="severity")
    severity_justification = CharFilter(lookup_expr="icontains")
    steps_to_reproduce = CharFilter(lookup_expr="icontains")
    unique_id_from_tool = CharFilter(lookup_expr="icontains")
    title = CharFilter(lookup_expr="icontains")
    exact_title = CharFilter(field_name="title", lookup_expr="iexact", help_text="Finding title exact match (case-insensitive)")
    product_name = CharFilter(lookup_expr="engagement__product__name__iexact", field_name="test", label=labels.ASSET_FILTERS_NAME_EXACT_LABEL)
    product_name_contains = CharFilter(lookup_expr="engagement__product__name__icontains", field_name="test", label=labels.ASSET_FILTERS_NAME_CONTAINS_LABEL)
    product_lifecycle = CharFilter(method=custom_filter, lookup_expr="engagement__product__lifecycle",
                                   field_name="test__engagement__product__lifecycle", label=labels.ASSET_FILTERS_CSV_LIFECYCLES_LABEL)
    # DateRangeFilter
    created = DateRangeFilter()
    date = DateRangeFilter()
    discovered_on = DateFilter(field_name="date", lookup_expr="exact")
    discovered_before = DateFilter(field_name="date", lookup_expr="lt")
    discovered_after = DateFilter(field_name="date", lookup_expr="gt")
    jira_creation = DateRangeFilter(field_name="jira_issue__jira_creation")
    jira_change = DateRangeFilter(field_name="jira_issue__jira_change")
    last_reviewed = DateRangeFilter()
    mitigated = DateRangeFilter()
    mitigated_on = DateTimeFilter(field_name="mitigated", lookup_expr="exact", method="filter_mitigated_on")
    mitigated_before = DateTimeFilter(field_name="mitigated", lookup_expr="lt")
    mitigated_after = DateTimeFilter(field_name="mitigated", lookup_expr="gt", label="Mitigated After", method="filter_mitigated_after")
    # NumberInFilter
    cwe = NumberInFilter(field_name="cwe", lookup_expr="in")
    defect_review_requested_by = NumberInFilter(field_name="defect_review_requested_by", lookup_expr="in")
    endpoints = NumberInFilter(field_name="endpoints", lookup_expr="in")
    epss_score = PercentageRangeFilter(
        field_name="epss_score",
        label="EPSS score range",
        help_text=(
            "The range of EPSS score percentages to filter on; the min input is a lower bound, "
            "the max is an upper bound. Leaving one empty will skip that bound (e.g., leaving "
            "the min bound input empty will filter only on the max bound -- filtering on "
            '"less than or equal"). Leading 0 required.'
        ))
    epss_percentile = PercentageRangeFilter(
        field_name="epss_percentile",
        label="EPSS percentile range",
        help_text=(
            "The range of EPSS percentiles to filter on; the min input is a lower bound, the max "
            "is an upper bound. Leaving one empty will skip that bound (e.g., leaving the min bound "
            'input empty will filter only on the max bound -- filtering on "less than or equal"). Leading 0 required.'
        ))
    found_by = NumberInFilter(field_name="found_by", lookup_expr="in")
    id = NumberInFilter(field_name="id", lookup_expr="in")
    last_reviewed_by = NumberInFilter(field_name="last_reviewed_by", lookup_expr="in")
    mitigated_by = NumberInFilter(field_name="mitigated_by", lookup_expr="in")
    nb_occurences = NumberInFilter(field_name="nb_occurences", lookup_expr="in")
    reporter = NumberInFilter(field_name="reporter", lookup_expr="in")
    scanner_confidence = NumberInFilter(field_name="scanner_confidence", lookup_expr="in")
    review_requested_by = NumberInFilter(field_name="review_requested_by", lookup_expr="in")
    reviewers = NumberInFilter(field_name="reviewers", lookup_expr="in")
    sast_source_line = NumberInFilter(field_name="sast_source_line", lookup_expr="in")
    sonarqube_issue = NumberInFilter(field_name="sonarqube_issue", lookup_expr="in")
    test__test_type = NumberInFilter(field_name="test__test_type", lookup_expr="in", label="Test Type")
    test__engagement = NumberInFilter(field_name="test__engagement", lookup_expr="in")
    test__engagement__product = NumberInFilter(field_name="test__engagement__product", lookup_expr="in")
    test__engagement__product__prod_type = NumberInFilter(field_name="test__engagement__product__prod_type", lookup_expr="in")
    finding_group = NumberInFilter(field_name="finding_group", lookup_expr="in")

    # ReportRiskAcceptanceFilter
    risk_acceptance = extend_schema_field(OpenApiTypes.NUMBER)(ReportRiskAcceptanceFilter())

    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Tag name contains")
    tags = CharFieldInFilter(
        field_name="tags__name",
        lookup_expr="in",
        help_text="Comma separated list of exact tags (uses OR for multiple values)")
    tags__and = CharFieldFilterANDExpression(
        field_name="tags__name",
        help_text="Comma separated list of exact tags to match with an AND expression")
    test__tags = CharFieldInFilter(
        field_name="test__tags__name",
        lookup_expr="in",
        help_text="Comma separated list of exact tags present on test (uses OR for multiple values)")
    test__tags__and = CharFieldFilterANDExpression(
        field_name="test__tags__name",
        help_text="Comma separated list of exact tags to match with an AND expression present on test")
    test__engagement__tags = CharFieldInFilter(
        field_name="test__engagement__tags__name",
        lookup_expr="in",
        help_text="Comma separated list of exact tags present on engagement (uses OR for multiple values)")
    test__engagement__tags__and = CharFieldFilterANDExpression(
        field_name="test__engagement__tags__name",
        help_text="Comma separated list of exact tags to match with an AND expression present on engagement")
    test__engagement__product__tags = CharFieldInFilter(
        field_name="test__engagement__product__tags__name",
        lookup_expr="in",
        help_text=labels.ASSET_FILTERS_CSV_TAGS_OR_HELP)
    test__engagement__product__tags__and = CharFieldFilterANDExpression(
        field_name="test__engagement__product__tags__name",
        help_text=labels.ASSET_FILTERS_CSV_TAGS_AND_HELP)
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Not Tag name contains", exclude="True")
    not_tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                                 help_text="Comma separated list of exact tags not present on model", exclude="True")
    not_test__tags = CharFieldInFilter(field_name="test__tags__name", lookup_expr="in", exclude="True", help_text="Comma separated list of exact tags present on test")
    not_test__engagement__tags = CharFieldInFilter(field_name="test__engagement__tags__name", lookup_expr="in",
                                                   help_text="Comma separated list of exact tags not present on engagement",
                                                   exclude="True")
    not_test__engagement__product__tags = CharFieldInFilter(
        field_name="test__engagement__product__tags__name",
        lookup_expr="in",
        help_text=labels.ASSET_FILTERS_CSV_TAGS_NOT_HELP,
        exclude="True")
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    outside_of_sla = extend_schema_field(OpenApiTypes.NUMBER)(FindingSLAFilter())

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("active", "active"),
            ("component_name", "component_name"),
            ("component_version", "component_version"),
            ("created", "created"),
            ("last_status_update", "last_status_update"),
            ("last_reviewed", "last_reviewed"),
            ("cwe", "cwe"),
            ("date", "date"),
            ("duplicate", "duplicate"),
            ("dynamic_finding", "dynamic_finding"),
            ("false_p", "false_p"),
            ("found_by", "found_by"),
            ("id", "id"),
            ("is_mitigated", "is_mitigated"),
            ("numerical_severity", "numerical_severity"),
            ("out_of_scope", "out_of_scope"),
            ("planned_remediation_date", "planned_remediation_date"),
            ("severity", "severity"),
            ("sla_expiration_date", "sla_expiration_date"),
            ("reviewers", "reviewers"),
            ("static_finding", "static_finding"),
            ("test__engagement__product__name", "test__engagement__product__name"),
            ("title", "title"),
            ("under_defect_review", "under_defect_review"),
            ("under_review", "under_review"),
            ("verified", "verified"),
        ),
    )

    class Meta:
        model = Finding
        exclude = ["url", "thread_id", "notes", "files",
                   "line", "cve"]

    def filter_mitigated_after(self, queryset, name, value):
        if value.hour == 0 and value.minute == 0 and value.second == 0:
            value = value.replace(hour=23, minute=59, second=59)

        return queryset.filter(mitigated__gt=value)

    def filter_mitigated_on(self, queryset, name, value):
        if value.hour == 0 and value.minute == 0 and value.second == 0:
            # we have a simple date without a time, lets get a range from this morning to tonight at 23:59:59:999
            nextday = value + timedelta(days=1)
            return queryset.filter(mitigated__gte=value, mitigated__lt=nextday)

        return queryset.filter(mitigated=value)

    def filter_mitigation_available(self, queryset, name, value):
        if value:
            return queryset.exclude(mitigation__isnull=True).exclude(mitigation__exact="")
        return queryset.filter(Q(mitigation__isnull=True) | Q(mitigation__exact=""))


class PercentageFilter(NumberFilter):
    def __init__(self, *args, **kwargs):
        kwargs["method"] = self.filter_percentage
        super().__init__(*args, **kwargs)

    def filter_percentage(self, queryset, name, value):
        value /= decimal.Decimal("100.0")
        # Provide some wiggle room for filtering since the UI rounds to two places (and because floats):
        # a user may enter 0.15, but we'll return everything in [0.0015, 0.0016).
        # To do this, add to our value 1^(whatever the exponent for our least significant digit place is), but ensure
        # that the exponent is at MOST the ten thousandths place so we don't show a range of e.g. [0.2, 0.3).
        exponent = min(value.normalize().as_tuple().exponent, -4)
        max_val = value + decimal.Decimal(f"1E{exponent}")
        lookup_kwargs = {
            f"{name}__gte": value,
            f"{name}__lt": max_val}
        return queryset.filter(**lookup_kwargs)


class ApiTemplateFindingFilter(DojoFilter):
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Tag name contains")
    tags = CharFieldInFilter(
        field_name="tags__name",
        lookup_expr="in",
        help_text="Comma separated list of exact tags (uses OR for multiple values)")
    tags__and = CharFieldFilterANDExpression(
        field_name="tags__name",
        help_text="Comma separated list of exact tags to match with an AND expression")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Not Tag name contains", exclude="True")
    not_tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                                 help_text="Comma separated list of exact tags not present on model", exclude="True")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("title", "title"),
            ("cwe", "cwe"),
        ),
    )

    class Meta:
        model = Finding_Template
        fields = ["id", "title", "cwe", "severity", "description",
                     "mitigation"]


class MetricsEndpointFilterHelper(FilterSet):
    start_date = DateFilter(field_name="date", label="Start Date", lookup_expr=("gt"))
    end_date = DateFilter(field_name="date", label="End Date", lookup_expr=("lt"))
    date = MetricsDateRangeFilter()
    finding__test__engagement__version = CharFilter(lookup_expr="icontains", label="Engagement Version")
    finding__severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES, label="Severity")
    endpoint__host = CharFilter(lookup_expr="icontains", label="Endpoint Host")
    finding_title = CharFilter(lookup_expr="icontains", label="Finding Title")
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)


class MetricsEndpointFilter(MetricsEndpointFilterHelper):
    finding__test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.none(),
        label=labels.ORG_FILTERS_LABEL)
    finding__test__engagement = ModelMultipleChoiceFilter(
        queryset=Engagement.objects.none(),
        label="Engagement")
    endpoint__tags = ModelMultipleChoiceFilter(
        field_name="endpoint__tags__name",
        to_field_name="name",
        label="Endpoint tags",
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"))
    finding__tags = ModelMultipleChoiceFilter(
        field_name="finding__tags__name",
        to_field_name="name",
        label="Finding tags",
        queryset=Finding.tags.tag_model.objects.all().order_by("name"))
    finding__test__tags = ModelMultipleChoiceFilter(
        field_name="finding__test__tags__name",
        to_field_name="name",
        label="Test tags",
        queryset=Test.tags.tag_model.objects.all().order_by("name"))
    finding__test__engagement__tags = ModelMultipleChoiceFilter(
        field_name="finding__test__engagement__tags__name",
        to_field_name="name",
        label="Engagement tags",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))
    finding__test__engagement__product__tags = ModelMultipleChoiceFilter(
        field_name="finding__test__engagement__product__tags__name",
        to_field_name="name",
        label=labels.ASSET_FILTERS_TAGS_ASSET_LABEL,
        queryset=Product.tags.tag_model.objects.all().order_by("name"))
    not_endpoint__tags = ModelMultipleChoiceFilter(
        field_name="endpoint__tags__name",
        to_field_name="name",
        exclude=True,
        label="Endpoint without tags",
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"))
    not_finding__tags = ModelMultipleChoiceFilter(
        field_name="finding__tags__name",
        to_field_name="name",
        exclude=True,
        label="Finding without tags",
        queryset=Finding.tags.tag_model.objects.all().order_by("name"))
    not_finding__test__tags = ModelMultipleChoiceFilter(
        field_name="finding__test__tags__name",
        to_field_name="name",
        exclude=True,
        label="Test without tags",
        queryset=Test.tags.tag_model.objects.all().order_by("name"))
    not_finding__test__engagement__tags = ModelMultipleChoiceFilter(
        field_name="finding__test__engagement__tags__name",
        to_field_name="name",
        exclude=True,
        label="Engagement without tags",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))
    not_finding__test__engagement__product__tags = ModelMultipleChoiceFilter(
        field_name="finding__test__engagement__product__tags__name",
        to_field_name="name",
        exclude=True,
        label=labels.ASSET_FILTERS_WITHOUT_TAGS_LABEL,
        queryset=Product.tags.tag_model.objects.all().order_by("name"))

    def __init__(self, *args, **kwargs):
        if args[0]:
            if args[0].get("start_date", "") or args[0].get("end_date", ""):
                args[0]._mutable = True
                args[0]["date"] = 8
                args[0]._mutable = False

        self.pid = None
        if "pid" in kwargs:
            self.pid = kwargs.pop("pid")

        super().__init__(*args, **kwargs)
        if self.pid:
            del self.form.fields["finding__test__engagement__product__prod_type"]
            self.form.fields["finding__test__engagement"].queryset = Engagement.objects.filter(
                product_id=self.pid,
            ).all()
        else:
            self.form.fields["finding__test__engagement"].queryset = get_authorized_engagements("view").order_by("name")

        if "finding__test__engagement__product__prod_type" in self.form.fields:
            self.form.fields[
                "finding__test__engagement__product__prod_type"].queryset = get_authorized_product_types("view")

    class Meta:
        model = Endpoint_Status
        exclude = ["last_modified", "endpoint", "finding"]


class MetricsEndpointFilterWithoutObjectLookups(MetricsEndpointFilterHelper, FindingTagStringFilter):
    finding__test__engagement__product__prod_type = CharFilter(
        field_name="finding__test__engagement__product__prod_type",
        lookup_expr="iexact",
        label=labels.ORG_FILTERS_NAME_LABEL,
        help_text=labels.ORG_FILTERS_NAME_HELP)
    finding__test__engagement__product__prod_type_contains = CharFilter(
        field_name="finding__test__engagement__product__prod_type",
        lookup_expr="icontains",
        label=labels.ORG_FILTERS_NAME_CONTAINS_LABEL,
        help_text=labels.ORG_FILTERS_NAME_CONTAINS_HELP)
    finding__test__engagement = CharFilter(
        field_name="finding__test__engagement",
        lookup_expr="iexact",
        label="Engagement Name",
        help_text="Search for Engagement names that are an exact match")
    finding__test__engagement_contains = CharFilter(
        field_name="finding__test__engagement",
        lookup_expr="icontains",
        label="Engagement Name Contains",
        help_text="Search for Engagement names that contain a given pattern")
    endpoint__tags_contains = CharFilter(
        label="Endpoint Tag Contains",
        field_name="endpoint__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Endpoint that contain a given pattern")
    endpoint__tags = CharFilter(
        label="Endpoint Tag",
        field_name="endpoint__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Endpoint that are an exact match")
    finding__tags_contains = CharFilter(
        label="Finding Tag Contains",
        field_name="finding__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    finding__tags = CharFilter(
        label="Finding Tag",
        field_name="finding__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    finding__test__tags_contains = CharFilter(
        label="Test Tag Contains",
        field_name="finding__test__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    finding__test__tags = CharFilter(
        label="Test Tag",
        field_name="finding__test__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    finding__test__engagement__tags_contains = CharFilter(
        label="Engagement Tag Contains",
        field_name="finding__test__engagement__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    finding__test__engagement__tags = CharFilter(
        label="Engagement Tag",
        field_name="finding__test__engagement__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    finding__test__engagement__product__tags_contains = CharFilter(
        label=labels.ASSET_FILTERS_TAG_ASSET_CONTAINS_LABEL,
        field_name="finding__test__engagement__product__tags__name",
        lookup_expr="icontains",
        help_text=labels.ASSET_FILTERS_TAG_ASSET_CONTAINS_HELP)
    finding__test__engagement__product__tags = CharFilter(
        label=labels.ASSET_FILTERS_TAG_ASSET_LABEL,
        field_name="finding__test__engagement__product__tags__name",
        lookup_expr="iexact",
        help_text=labels.ASSET_FILTERS_TAG_ASSET_HELP)

    not_endpoint__tags_contains = CharFilter(
        label="Endpoint Tag Does Not Contain",
        field_name="endpoint__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Endpoint that contain a given pattern, and exclude them",
        exclude=True)
    not_endpoint__tags = CharFilter(
        label="Not Endpoint Tag",
        field_name="endpoint__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Endpoint that are an exact match, and exclude them",
        exclude=True)
    not_finding__tags_contains = CharFilter(
        label="Finding Tag Does Not Contain",
        field_name="finding__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern, and exclude them",
        exclude=True)
    not_finding__tags = CharFilter(
        label="Not Finding Tag",
        field_name="finding__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match, and exclude them",
        exclude=True)
    not_finding__test__tags_contains = CharFilter(
        label="Test Tag Does Not Contain",
        field_name="finding__test__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Test that contain a given pattern, and exclude them",
        exclude=True)
    not_finding__test__tags = CharFilter(
        label="Not Test Tag",
        field_name="finding__test__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Test that are an exact match, and exclude them",
        exclude=True)
    not_finding__test__engagement__tags_contains = CharFilter(
        label="Engagement Tag Does Not Contain",
        field_name="finding__test__engagement__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Engagement that contain a given pattern, and exclude them",
        exclude=True)
    not_finding__test__engagement__tags = CharFilter(
        label="Not Engagement Tag",
        field_name="finding__test__engagement__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Engagement that are an exact match, and exclude them",
        exclude=True)
    not_finding__test__engagement__product__tags_contains = CharFilter(
        label=labels.ASSET_FILTERS_TAG_NOT_CONTAIN_LABEL,
        field_name="finding__test__engagement__product__tags__name",
        lookup_expr="icontains",
        help_text=labels.ASSET_FILTERS_TAG_NOT_CONTAIN_HELP,
        exclude=True)
    not_finding__test__engagement__product__tags = CharFilter(
        label=labels.ASSET_FILTERS_TAG_NOT_LABEL,
        field_name="finding__test__engagement__product__tags__name",
        lookup_expr="iexact",
        help_text=labels.ASSET_FILTERS_TAG_NOT_HELP,
        exclude=True)

    def __init__(self, *args, **kwargs):
        if args[0]:
            if args[0].get("start_date", "") or args[0].get("end_date", ""):
                args[0]._mutable = True
                args[0]["date"] = 8
                args[0]._mutable = False
        self.pid = None
        if "pid" in kwargs:
            self.pid = kwargs.pop("pid")
        super().__init__(*args, **kwargs)
        if self.pid:
            del self.form.fields["finding__test__engagement__product__prod_type"]

    class Meta:
        model = Endpoint_Status
        exclude = ["last_modified", "endpoint", "finding"]


class EndpointFilterHelper(FilterSet):
    protocol = CharFilter(lookup_expr="icontains")
    userinfo = CharFilter(lookup_expr="icontains")
    host = CharFilter(lookup_expr="icontains")
    port = NumberFilter()
    path = CharFilter(lookup_expr="icontains")
    query = CharFilter(lookup_expr="icontains")
    fragment = CharFilter(lookup_expr="icontains")
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("product", "product"),
            ("host", "host"),
            ("id", "id"),
            ("active_finding_count", "active_finding_count"),
        ),
        field_labels={
            "active_finding_count": "Active Findings Count",
        },
    )


class EndpointFilter(EndpointFilterHelper, DojoFilter):
    product = ModelMultipleChoiceFilter(
        queryset=Product.objects.none(),
        label=labels.ASSET_FILTERS_LABEL)
    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        label="Endpoint Tags",
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"))
    findings__tags = ModelMultipleChoiceFilter(
        field_name="findings__tags__name",
        to_field_name="name",
        label="Finding Tags",
        queryset=Finding.tags.tag_model.objects.all().order_by("name"))
    findings__test__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__tags__name",
        to_field_name="name",
        label="Test Tags",
        queryset=Test.tags.tag_model.objects.all().order_by("name"))
    findings__test__engagement__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__engagement__tags__name",
        to_field_name="name",
        label="Engagement Tags",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))
    findings__test__engagement__product__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__engagement__product__tags__name",
        to_field_name="name",
        label=labels.ASSET_FILTERS_TAGS_ASSET_LABEL,
        queryset=Product.tags.tag_model.objects.all().order_by("name"))
    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        label="Not Endpoint Tags",
        exclude=True,
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"))
    not_findings__tags = ModelMultipleChoiceFilter(
        field_name="findings__tags__name",
        to_field_name="name",
        label="Not Finding Tags",
        exclude=True,
        queryset=Finding.tags.tag_model.objects.all().order_by("name"))
    not_findings__test__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__tags__name",
        to_field_name="name",
        label="Not Test Tags",
        exclude=True,
        queryset=Test.tags.tag_model.objects.all().order_by("name"))
    not_findings__test__engagement__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__engagement__tags__name",
        to_field_name="name",
        label="Not Engagement Tags",
        exclude=True,
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))
    not_findings__test__engagement__product__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__engagement__product__tags__name",
        to_field_name="name",
        label=labels.ASSET_FILTERS_NOT_TAGS_ASSET_LABEL,
        exclude=True,
        queryset=Product.tags.tag_model.objects.all().order_by("name"))

    def __init__(self, *args, **kwargs):
        self.user = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)
        self.form.fields["product"].queryset = get_authorized_products("view")

    @property
    def qs(self):
        parent = super().qs
        return get_authorized_endpoints_for_queryset("view", parent)

    class Meta:
        model = Endpoint
        exclude = ["findings", "inherited_tags"]


class EndpointFilterWithoutObjectLookups(EndpointFilterHelper):
    product = NumberFilter(widget=HiddenInput())
    product__name = CharFilter(
        field_name="product__name",
        lookup_expr="iexact",
        label=labels.ASSET_FILTERS_NAME_LABEL,
        help_text=labels.ASSET_FILTERS_NAME_HELP)
    product__name_contains = CharFilter(
        field_name="product__name",
        lookup_expr="icontains",
        label=labels.ASSET_FILTERS_NAME_CONTAINS_LABEL,
        help_text=labels.ASSET_FILTERS_NAME_CONTAINS_HELP)

    tags_contains = CharFilter(
        label="Endpoint Tag Contains",
        field_name="tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Endpoint that contain a given pattern")
    tags = CharFilter(
        label="Endpoint Tag",
        field_name="tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Endpoint that are an exact match")
    findings__tags_contains = CharFilter(
        label="Finding Tag Contains",
        field_name="findings__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    findings__tags = CharFilter(
        label="Finding Tag",
        field_name="findings__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    findings__test__tags_contains = CharFilter(
        label="Test Tag Contains",
        field_name="findings__test__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    findings__test__tags = CharFilter(
        label="Test Tag",
        field_name="findings__test__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    findings__test__engagement__tags_contains = CharFilter(
        label="Engagement Tag Contains",
        field_name="findings__test__engagement__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    findings__test__engagement__tags = CharFilter(
        label="Engagement Tag",
        field_name="findings__test__engagement__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    findings__test__engagement__product__tags_contains = CharFilter(
        label=labels.ASSET_FILTERS_TAG_ASSET_CONTAINS_LABEL,
        field_name="findings__test__engagement__product__tags__name",
        lookup_expr="icontains",
        help_text=labels.ASSET_FILTERS_TAG_ASSET_CONTAINS_HELP)
    findings__test__engagement__product__tags = CharFilter(
        label=labels.ASSET_FILTERS_TAG_ASSET_LABEL,
        field_name="findings__test__engagement__product__tags__name",
        lookup_expr="iexact",
        help_text=labels.ASSET_FILTERS_TAG_ASSET_HELP)

    not_tags_contains = CharFilter(
        label="Endpoint Tag Does Not Contain",
        field_name="tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Endpoint that contain a given pattern, and exclude them",
        exclude=True)
    not_tags = CharFilter(
        label="Not Endpoint Tag",
        field_name="tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Endpoint that are an exact match, and exclude them",
        exclude=True)
    not_findings__tags_contains = CharFilter(
        label="Finding Tag Does Not Contain",
        field_name="findings__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern, and exclude them",
        exclude=True)
    not_findings__tags = CharFilter(
        label="Not Finding Tag",
        field_name="findings__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match, and exclude them",
        exclude=True)
    not_findings__test__tags_contains = CharFilter(
        label="Test Tag Does Not Contain",
        field_name="findings__test__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Test that contain a given pattern, and exclude them",
        exclude=True)
    not_findings__test__tags = CharFilter(
        label="Not Test Tag",
        field_name="findings__test__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Test that are an exact match, and exclude them",
        exclude=True)
    not_findings__test__engagement__tags_contains = CharFilter(
        label="Engagement Tag Does Not Contain",
        field_name="findings__test__engagement__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Engagement that contain a given pattern, and exclude them",
        exclude=True)
    not_findings__test__engagement__tags = CharFilter(
        label="Not Engagement Tag",
        field_name="findings__test__engagement__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Engagement that are an exact match, and exclude them",
        exclude=True)
    not_findings__test__engagement__product__tags_contains = CharFilter(
        label=labels.ASSET_FILTERS_TAG_NOT_CONTAIN_LABEL,
        field_name="findings__test__engagement__product__tags__name",
        lookup_expr="icontains",
        help_text=labels.ASSET_FILTERS_TAG_NOT_CONTAIN_HELP,
        exclude=True)
    not_findings__test__engagement__product__tags = CharFilter(
        label=labels.ASSET_FILTERS_TAG_NOT_LABEL,
        field_name="findings__test__engagement__product__tags__name",
        lookup_expr="iexact",
        help_text=labels.ASSET_FILTERS_TAG_NOT_HELP,
        exclude=True)

    def __init__(self, *args, **kwargs):
        self.user = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)

    @property
    def qs(self):
        parent = super().qs
        return get_authorized_endpoints_for_queryset("view", parent)

    class Meta:
        model = Endpoint
        exclude = ["findings", "inherited_tags", "product"]


class ApiEndpointFilter(DojoFilter):
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Tag name contains")
    tags = CharFieldInFilter(
        field_name="tags__name",
        lookup_expr="in",
        help_text="Comma separated list of exact tags (uses OR for multiple values)")
    tags__and = CharFieldFilterANDExpression(
        field_name="tags__name",
        help_text="Comma separated list of exact tags to match with an AND expression")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Not Tag name contains", exclude="True")
    not_tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                                 help_text="Comma separated list of exact tags not present on model", exclude="True")
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("host", "host"),
            ("product", "product"),
            ("id", "id"),
            ("active_finding_count", "active_finding_count"),
        ),
        field_labels={
            "active_finding_count": "Active Findings Count",
        },
    )

    class Meta:
        model = Endpoint
        fields = ["id", "protocol", "userinfo", "host", "port", "path", "query", "fragment", "product"]


class ApiRiskAcceptanceFilter(DojoFilter):
    created = DateRangeFilter()
    updated = DateRangeFilter()

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
            ("created", "created"),
            ("updated", "updated"),
        ),
    )

    class Meta:
        model = Risk_Acceptance
        fields = {
            "name": ["exact", "icontains"],
            "accepted_findings": ["exact"],
            "recommendation": ["exact"],
            "recommendation_details": ["exact", "icontains"],
            "decision": ["exact"],
            "decision_details": ["exact", "icontains"],
            "accepted_by": ["exact", "icontains"],
            "owner": ["exact"],
            "expiration_date": ["exact", "gt", "lt", "gte", "lte"],
            "expiration_date_warned": ["exact", "gt", "lt", "gte", "lte"],
            "expiration_date_handled": ["exact", "gt", "lt", "gte", "lte"],
            "reactivate_expired": ["exact"],
            "restart_sla_expired": ["exact"],
            "notes": ["exact"],
            "created": ["exact", "gt", "lt", "gte", "lte"],
            "updated": ["exact", "gt", "lt", "gte", "lte"],
        }


class ApiAppAnalysisFilter(DojoFilter):
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Tag name contains")
    tags = CharFieldInFilter(
        field_name="tags__name",
        lookup_expr="in",
        help_text="Comma separated list of exact tags (uses OR for multiple values)")
    tags__and = CharFieldFilterANDExpression(
        field_name="tags__name",
        help_text="Comma separated list of exact tags to match with an AND expression")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Not Tag name contains", exclude="True")
    not_tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                                 help_text="Comma separated list of exact tags not present on model", exclude="True")

    class Meta:
        model = App_Analysis
        fields = ["product", "name", "user", "version"]


class EndpointReportFilter(DojoFilter):
    protocol = CharFilter(lookup_expr="icontains")
    userinfo = CharFilter(lookup_expr="icontains")
    host = CharFilter(lookup_expr="icontains")
    port = NumberFilter()
    path = CharFilter(lookup_expr="icontains")
    query = CharFilter(lookup_expr="icontains")
    fragment = CharFilter(lookup_expr="icontains")
    finding__severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES, label="Severity")
    finding__mitigated = ReportBooleanFilter(label="Finding Mitigated")

    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")

    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)

    class Meta:
        model = Endpoint
        exclude = ["product"]


class UserFilter(DojoFilter):
    first_name = CharFilter(lookup_expr="icontains")
    last_name = CharFilter(lookup_expr="icontains")
    username = CharFilter(lookup_expr="icontains")
    email = CharFilter(lookup_expr="icontains")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("username", "username"),
            ("last_name", "last_name"),
            ("first_name", "first_name"),
            ("email", "email"),
            ("is_active", "is_active"),
            ("is_superuser", "is_superuser"),
            ("is_staff", "is_staff"),
            ("date_joined", "date_joined"),
            ("last_login", "last_login"),
        ),
        field_labels={
            "username": "User Name",
            "is_active": "Active",
            "is_superuser": "Superuser",
            "is_staff": "Staff",
        },
    )

    class Meta:
        model = Dojo_User
        fields = ["is_superuser", "is_staff", "is_active", "first_name", "last_name", "username", "email"]


# TestImportFilter and TestImportFindingActionFilter live in dojo/test/ui/filters.py and are
# re-exported at the bottom of this module for backward compatibility.


# LogEntryFilter and PgHistoryFilter live in dojo/auditlog/filters.py and are
# re-exported at the bottom of this module for backward compatibility.
# TestTypeFilter lives in dojo/test/ui/filters.py and is re-exported below.


class DevelopmentEnvironmentFilter(DojoFilter):
    name = CharFilter(lookup_expr="icontains")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
        ),
    )

    class Meta:
        model = Development_Environment
        exclude = []
        include = ("name",)


class NoteTypesFilter(DojoFilter):
    name = CharFilter(lookup_expr="icontains")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
            ("description", "description"),
            ("is_single", "is_single"),
            ("is_mandatory", "is_mandatory"),
        ),
    )

    class Meta:
        model = Note_Type
        exclude = []
        include = ("name", "is_single", "description")

# ==============================
# Defect Dojo Engaegment Surveys
# ==============================


class QuestionnaireFilter(FilterSet):
    name = CharFilter(lookup_expr="icontains")
    description = CharFilter(lookup_expr="icontains")
    active = BooleanFilter()

    class Meta:
        model = Engagement_Survey
        exclude = ["questions"]

    survey_set = FilterSet


class QuestionTypeFilter(ChoiceFilter):
    def any(self, qs, name):
        return qs.all()

    def text_question(self, qs, name):
        return qs.filter(polymorphic_ctype=ContentType.objects.get_for_model(TextQuestion))

    def choice_question(self, qs, name):
        return qs.filter(polymorphic_ctype=ContentType.objects.get_for_model(ChoiceQuestion))

    options = {
        None: (_("Any"), any),
        1: (_("Text Question"), text_question),
        2: (_("Choice Question"), choice_question),
    }

    def __init__(self, *args, **kwargs):
        kwargs["choices"] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = None
        return self.options[value][1](self, qs, self.options[value][0])


class ApiUserFilter(filters.FilterSet):
    last_login = filters.DateFromToRangeFilter()
    date_joined = filters.DateFromToRangeFilter()
    is_active = filters.BooleanFilter()
    is_superuser = filters.BooleanFilter()
    username = filters.CharFilter(lookup_expr="icontains")
    first_name = filters.CharFilter(lookup_expr="icontains")
    last_name = filters.CharFilter(lookup_expr="icontains")
    email = filters.CharFilter(lookup_expr="icontains")
    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "first_name",
            "last_name",
            "email",
            "is_active",
            "is_superuser",
            "last_login",
            "date_joined",
        ]

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("username", "username"),
            ("last_name", "last_name"),
            ("first_name", "first_name"),
            ("email", "email"),
            ("is_active", "is_active"),
            ("is_superuser", "is_superuser"),
            ("date_joined", "date_joined"),
            ("last_login", "last_login"),
        ),
    )


with warnings.catch_warnings(action="ignore", category=ManagerInheritanceWarning):
    class QuestionFilter(FilterSet):
        text = CharFilter(lookup_expr="icontains")
        type = QuestionTypeFilter()

        class Meta:
            model = Question
            exclude = ["polymorphic_ctype", "created", "modified", "order"]

        question_set = FilterSet


from dojo.auditlog.filters import LogEntryFilter, PgHistoryFilter  # noqa: E402, F401 -- backward compat
