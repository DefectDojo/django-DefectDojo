from collections import OrderedDict

import django_filters as djf

from ..filters import (
    DateRangeFilter,
    DojoFilterSetNew,
    OptionalBooleanFilter,
    SEVERITY_CHOICES,
    get_ordering_filter,
)
from ..models_base import User
from ..models import Engagement, Finding, Product, Product_Type, Test, Test_Type
from .builders import BUILDER_REGISTRY
from .models import ReportNG


class ReportNGFilterSet(DojoFilterSetNew):
    """
    Filter set for ReportNG objects.
    """

    title = djf.CharFilter(lookup_expr="icontains", label="Report Title")
    builder_code = djf.ChoiceFilter(label="Report Builder")
    products = djf.ModelMultipleChoiceFilter(
        queryset=Product.objects.for_user, conjoined=True, label="Products (conjoined)"
    )
    products.always_filter = False
    created = DateRangeFilter()
    status = djf.MultipleChoiceFilter(choices=ReportNG.STATUS_CHOICES, label="Status")
    requester = djf.ModelChoiceFilter(
        # Only users with accessible reports
        queryset=lambda req: User.objects.filter(
            ReportNG.objects.for_user.as_q(req).prefix("reportng")
        ).distinct(),
        label="Requester",
    )

    o = get_ordering_filter(
        OrderedDict(
            (
                ("title", "Report Title"),
                ("created", "Creation Date"),
                ("status", "Status"),
                ("builder_code", "Report Builder"),
            )
        )
    )

    bulk_actions = ("delete",)

    class Meta:
        model = ReportNG
        fields = ["title", "builder_code", "products", "created", "status", "requester"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields["builder_code"].choices = [
            (builder.code, builder.name)
            for builder in sorted(BUILDER_REGISTRY.values(), key=lambda k: k.name)
        ]


class ProductFilterSet(DojoFilterSetNew):
    """
    Filter set for Product objects.
    """

    name = djf.CharFilter(lookup_expr="icontains", label="Product Name")
    prod_type = djf.ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.all(), label="Product Type"
    )

    o = get_ordering_filter(
        OrderedDict((("name", "Product Name"), ("prod_type__name", "Product Type")))
    )

    class Meta:
        model = Product
        fields = []


class EngagementFilterSet(DojoFilterSetNew):
    """
    Filter set for Engagement objects.
    """

    name = djf.CharFilter(lookup_expr="icontains", label="Name")
    lead = djf.ModelChoiceFilter(
        queryset=User.objects.filter(engagement__lead__isnull=False).distinct()
    )

    o = get_ordering_filter(OrderedDict((("name", "Name"),)))

    class Meta:
        model = Engagement
        fields = []


class TestFilterSet(DojoFilterSetNew):
    """
    Filter set for Test objects.
    """

    title = djf.CharFilter(lookup_expr="icontains", label="Title")
    test_type = djf.ModelMultipleChoiceFilter(queryset=Test_Type.objects.for_user)
    lead = djf.ModelMultipleChoiceFilter(
        queryset=User.objects.filter(test__lead__isnull=False).distinct()
    )

    o = get_ordering_filter(
        OrderedDict(
            (
                ("title", "Title"),
                ("test_type__name", "Name of Test Type"),
                ("lead__username", "Username of Lead"),
            )
        )
    )

    class Meta:
        model = Test
        fields = []


class FindingFilterSet(DojoFilterSetNew):
    """
    Filter set for Finding objects.
    """

    title = djf.CharFilter(lookup_expr="icontains", label="Title")
    date = DateRangeFilter()
    severity = djf.MultipleChoiceFilter(choices=SEVERITY_CHOICES)
    test__test_type = djf.ModelMultipleChoiceFilter(queryset=Test_Type.objects.all())
    cwe = djf.MultipleChoiceFilter(choices=[])
    cve = djf.CharFilter(lookup_expr="icontains", label="CVE contains")
    sourcefile = djf.CharFilter(lookup_expr="icontains", label="Source file contains")
    sourcefilepath = djf.CharFilter(
        lookup_expr="icontains", label="Source file path contains"
    )
    line = djf.NumberFilter()
    param = djf.CharFilter(lookup_expr="icontains")
    payload = djf.CharFilter(lookup_expr="icontains")
    static_finding = OptionalBooleanFilter()
    dynamic_finding = OptionalBooleanFilter()
    active = OptionalBooleanFilter()
    verified = OptionalBooleanFilter()
    false_p = OptionalBooleanFilter(label="False positive")
    duplicate = OptionalBooleanFilter()
    out_of_scope = OptionalBooleanFilter()
    reporter = djf.ModelMultipleChoiceFilter(queryset=User.objects.all())
    reviewers = djf.ModelMultipleChoiceFilter(queryset=User.objects.all())
    under_review = OptionalBooleanFilter()
    review_requested_by = djf.ModelMultipleChoiceFilter(queryset=User.objects.all())
    under_defect_review = OptionalBooleanFilter()
    defect_review_requested_by = djf.ModelMultipleChoiceFilter(
        queryset=User.objects.all()
    )

    o = get_ordering_filter(
        OrderedDict(
            (
                ("title", "Title"),
                ("sourcefile", "Source File"),
                ("sourcefilepath", "Source File Path"),
                ("cve", "CVE"),
                ("cwe", "CWE"),
            )
        )
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields["cwe"].choices = (
            (cwe, cwe)
            for cwe in sorted(
                set(self.queryset.exclude(cwe=None).values_list("cwe", flat=True))
            )
        )

    class Meta:
        model = Finding
        fields = []
