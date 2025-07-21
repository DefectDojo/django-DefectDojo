# #  metrics
import collections
import logging
import operator
from calendar import monthrange
from datetime import date, datetime, timedelta

from dateutil.relativedelta import relativedelta
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.db.models import Case, Count, F, IntegerField, Q, Sum, Value, When
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.utils.html import escape
from django.utils.translation import gettext as _
from django.views.decorators.cache import cache_page
from django.views.decorators.vary import vary_on_cookie

from dojo.authorization.authorization import user_has_permission_or_403
from dojo.authorization.roles_permissions import Permissions
from dojo.filters import UserFilter
from dojo.forms import ProductTagCountsForm, ProductTypeCountsForm, SimpleMetricsForm
from dojo.metrics.utils import (
    endpoint_queries,
    finding_queries,
    findings_queryset,
    get_accepted_in_period_details,
    get_closed_in_period_details,
    get_in_period_details,
    identify_view,
    severity_count,
)
from dojo.models import Dojo_User, Finding, Product, Product_Type, Risk_Acceptance
from dojo.product.queries import get_authorized_products
from dojo.product_type.queries import get_authorized_product_types
from dojo.utils import (
    add_breadcrumb,
    count_findings,
    findings_this_period,
    get_page_items,
    get_punchcard_data,
    get_system_setting,
    opened_in_period,
    queryset_check,
)

logger = logging.getLogger(__name__)


"""
Greg, Jay
status: in production
generic metrics method
"""


def critical_product_metrics(request, mtype):
    template = "dojo/metrics.html"
    page_name = _("Critical Product Metrics")
    critical_products = get_authorized_product_types(Permissions.Product_Type_View)
    critical_products = critical_products.filter(critical_product=True)
    add_breadcrumb(title=page_name, top_level=not len(request.GET), request=request)
    return render(request, template, {
        "name": page_name,
        "critical_prods": critical_products,
        "url_prefix": get_system_setting("url_prefix"),
    })


# @cache_page(60 * 5)  # cache for 5 minutes
@vary_on_cookie
def metrics(request, mtype):
    template = "dojo/metrics.html"
    show_pt_filter = True
    view = identify_view(request)
    page_name = _("Metrics")

    if mtype != "All":
        pt = Product_Type.objects.filter(id=mtype)
        request.GET._mutable = True
        request.GET.appendlist("test__engagement__product__prod_type", mtype)
        request.GET._mutable = False
        show_pt_filter = False
        page_name = _("%(product_type)s Metrics") % {"product_type": mtype}
        prod_type = pt
    elif "test__engagement__product__prod_type" in request.GET:
        prod_type = Product_Type.objects.filter(id__in=request.GET.getlist("test__engagement__product__prod_type", []))
    else:
        prod_type = get_authorized_product_types(Permissions.Product_Type_View)
    # legacy code calls has 'prod_type' as 'related_name' for product.... so weird looking prefetch
    prod_type = prod_type.prefetch_related("prod_type")

    filters = {}
    if view == "Finding":
        page_name = _("Product Type Metrics by Findings")
        filters = finding_queries(prod_type, request)
    elif view == "Endpoint":
        page_name = _("Product Type Metrics by Affected Endpoints")
        filters = endpoint_queries(prod_type, request)

    all_findings = findings_queryset(queryset_check(filters["all"]))

    in_period_counts, in_period_details, age_detail = get_in_period_details(all_findings)

    accepted_in_period_details = get_accepted_in_period_details(
        findings_queryset(filters["accepted"]),
    )

    closed_in_period_counts, closed_in_period_details = get_closed_in_period_details(
        findings_queryset(filters["closed"]),
    )

    punchcard = []
    ticks = []

    if "view" in request.GET and request.GET["view"] == "dashboard":
        punchcard, ticks = get_punchcard_data(all_findings, filters["start_date"], filters["weeks_between"], view)
        page_name = _("%(team_name)s Metrics") % {"team_name": get_system_setting("team_name")}
        template = "dojo/dashboard-metrics.html"

    add_breadcrumb(title=page_name, top_level=not len(request.GET), request=request)

    return render(request, template, {
        "name": page_name,
        "start_date": filters["start_date"],
        "end_date": filters["end_date"],
        "findings": all_findings,
        "max_findings_details": 50,
        "opened_per_month": filters["monthly_counts"]["opened_per_period"],
        "active_per_month": filters["monthly_counts"]["active_per_period"],
        "opened_per_week": filters["weekly_counts"]["opened_per_period"],
        "accepted_per_month": filters["monthly_counts"]["accepted_per_period"],
        "accepted_per_week": filters["weekly_counts"]["accepted_per_period"],
        "top_ten_products": filters["top_ten"],
        "age_detail": age_detail,
        "in_period_counts": in_period_counts,
        "in_period_details": in_period_details,
        "accepted_in_period_counts": filters["accepted_count"],
        "accepted_in_period_details": accepted_in_period_details,
        "closed_in_period_counts": closed_in_period_counts,
        "closed_in_period_details": closed_in_period_details,
        "punchcard": punchcard,
        "ticks": ticks,
        "form": filters.get("form", None),
        "show_pt_filter": show_pt_filter,
    })


"""
Jay
status: in production
simple metrics for easy reporting
"""


@cache_page(60 * 5)  # cache for 5 minutes
@vary_on_cookie
def simple_metrics(request):
    page_name = _("Simple Metrics")
    now = timezone.now()

    if request.method == "POST":
        form = SimpleMetricsForm(request.POST)
        if form.is_valid():
            now = form.cleaned_data["date"]
            form = SimpleMetricsForm({"date": now})
    else:
        form = SimpleMetricsForm({"date": now})

    findings_by_product_type = collections.OrderedDict()

    # for each product type find each product with open findings and
    # count the S0, S1, S2 and S3
    # legacy code calls has 'prod_type' as 'related_name' for product.... so weird looking prefetch
    product_types = get_authorized_product_types(Permissions.Product_Type_View)
    product_types = product_types.prefetch_related("prod_type")
    for pt in product_types:
        total_critical = []
        total_high = []
        total_medium = []
        total_low = []
        total_info = []
        total_opened = []
        findings_broken_out = {}

        total = Finding.objects.filter(test__engagement__product__prod_type=pt,
                                       false_p=False,
                                       duplicate=False,
                                       out_of_scope=False,
                                       date__month=now.month,
                                       date__year=now.year,
                                       )

        closed = Finding.objects.filter(test__engagement__product__prod_type=pt,
                                       false_p=False,
                                       duplicate=False,
                                       out_of_scope=False,
                                       active=False,
                                       is_mitigated=True,
                                       mitigated__isnull=False,
                                       mitigated__month=now.month,
                                       mitigated__year=now.year,
                                       )

        if get_system_setting("enforce_verified_status", True) or get_system_setting("enforce_verified_status_metrics", True):
            total = total.filter(verified=True)
            closed = closed.filter(verified=True)

        total = total.distinct()
        closed = closed.distinct()

        for f in total:
            if f.severity == "Critical":
                total_critical.append(f)
            elif f.severity == "High":
                total_high.append(f)
            elif f.severity == "Medium":
                total_medium.append(f)
            elif f.severity == "Low":
                total_low.append(f)
            else:
                total_info.append(f)

            if f.date.year == now.year and f.date.month == now.month:
                total_opened.append(f)

        findings_broken_out["Total"] = len(total)
        findings_broken_out["S0"] = len(total_critical)
        findings_broken_out["S1"] = len(total_high)
        findings_broken_out["S2"] = len(total_medium)
        findings_broken_out["S3"] = len(total_low)
        findings_broken_out["S4"] = len(total_info)

        findings_broken_out["Opened"] = len(total_opened)
        findings_broken_out["Closed"] = len(closed)

        findings_by_product_type[pt] = findings_broken_out

    add_breadcrumb(title=page_name, top_level=True, request=request)

    return render(request, "dojo/simple_metrics.html", {
        "findings": findings_by_product_type,
        "name": page_name,
        "metric": True,
        "user": request.user,
        "form": form,
    })


# @cache_page(60 * 5)  # cache for 5 minutes
# @vary_on_cookie
def product_type_counts(request):
    form = ProductTypeCountsForm()
    opened_in_period_list = []
    oip = None
    cip = None
    aip = None
    all_current_in_pt = None
    top_ten = None
    pt = None
    today = timezone.now()
    first_of_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    mid_month = first_of_month.replace(day=15, hour=23, minute=59, second=59, microsecond=999999)
    end_of_month = mid_month.replace(day=monthrange(today.year, today.month)[1], hour=23, minute=59, second=59,
                                     microsecond=999999)
    start_date = first_of_month
    end_date = end_of_month

    if request.method == "GET" and "month" in request.GET and "year" in request.GET and "product_type" in request.GET:
        form = ProductTypeCountsForm(request.GET)
        if form.is_valid():
            pt = form.cleaned_data["product_type"]
            user_has_permission_or_403(request.user, pt, Permissions.Product_Type_View)
            month = int(form.cleaned_data["month"])
            year = int(form.cleaned_data["year"])
            first_of_month = first_of_month.replace(month=month, year=year)

            month_requested = datetime(year, month, 1)

            end_of_month = month_requested.replace(day=monthrange(month_requested.year, month_requested.month)[1],
                                                   hour=23, minute=59, second=59, microsecond=999999)
            start_date = first_of_month
            start_date = datetime(start_date.year,
                                  start_date.month, start_date.day,
                                  tzinfo=timezone.get_current_timezone())
            end_date = end_of_month
            end_date = datetime(end_date.year,
                                end_date.month, end_date.day,
                                tzinfo=timezone.get_current_timezone())

            oip = opened_in_period(start_date, end_date, test__engagement__product__prod_type=pt)

            # trending data - 12 months
            opened_in_period_list.extend(opened_in_period(start_date + relativedelta(months=-x), end_of_month + relativedelta(months=-x),
                                     test__engagement__product__prod_type=pt) for x in range(12, 0, -1))

            opened_in_period_list.append(oip)

            closed_in_period = Finding.objects.filter(mitigated__date__range=[start_date, end_date],
                                                      test__engagement__product__prod_type=pt,
                                                      severity__in=("Critical", "High", "Medium", "Low")).values(
                "numerical_severity").annotate(Count("numerical_severity")).order_by("numerical_severity")

            total_closed_in_period = Finding.objects.filter(mitigated__date__range=[start_date, end_date],
                                                            test__engagement__product__prod_type=pt,
                                                            severity__in=(
                                                                "Critical", "High", "Medium", "Low")).aggregate(
                total=Sum(
                    Case(When(severity__in=("Critical", "High", "Medium", "Low"),
                              then=Value(1)),
                         output_field=IntegerField())))["total"]

            if get_system_setting("enforce_verified_status", True) or get_system_setting("enforce_verified_status_metrics", True):
                overall_in_pt = Finding.objects.filter(date__lt=end_date,
                                                    verified=True,
                                                    false_p=False,
                                                    duplicate=False,
                                                    out_of_scope=False,
                                                    mitigated__isnull=True,
                                                    test__engagement__product__prod_type=pt,
                                                    severity__in=("Critical", "High", "Medium", "Low")).values(
                    "numerical_severity").annotate(Count("numerical_severity")).order_by("numerical_severity")

                total_overall_in_pt = Finding.objects.filter(date__lte=end_date,
                                                            verified=True,
                                                            false_p=False,
                                                            duplicate=False,
                                                            out_of_scope=False,
                                                            mitigated__isnull=True,
                                                            test__engagement__product__prod_type=pt,
                                                            severity__in=("Critical", "High", "Medium", "Low")).aggregate(
                    total=Sum(
                        Case(When(severity__in=("Critical", "High", "Medium", "Low"),
                                then=Value(1)),
                            output_field=IntegerField())))["total"]

                all_current_in_pt = Finding.objects.filter(date__lte=end_date,
                                                        verified=True,
                                                        false_p=False,
                                                        duplicate=False,
                                                        out_of_scope=False,
                                                        mitigated__isnull=True,
                                                        test__engagement__product__prod_type=pt,
                                                        severity__in=(
                                                            "Critical", "High", "Medium", "Low")).prefetch_related(
                    "test__engagement__product",
                    "test__engagement__product__prod_type",
                    "test__engagement__risk_acceptance",
                    "reporter").order_by(
                    "numerical_severity")

                top_ten = Product.objects.filter(engagement__test__finding__date__lte=end_date,
                                                engagement__test__finding__verified=True,
                                                engagement__test__finding__false_p=False,
                                                engagement__test__finding__duplicate=False,
                                                engagement__test__finding__out_of_scope=False,
                                                engagement__test__finding__mitigated__isnull=True,
                                                engagement__test__finding__severity__in=(
                                                    "Critical", "High", "Medium", "Low"),
                                                prod_type=pt)
            else:
                overall_in_pt = Finding.objects.filter(date__lt=end_date,
                                                    false_p=False,
                                                    duplicate=False,
                                                    out_of_scope=False,
                                                    mitigated__isnull=True,
                                                    test__engagement__product__prod_type=pt,
                                                    severity__in=("Critical", "High", "Medium", "Low")).values(
                    "numerical_severity").annotate(Count("numerical_severity")).order_by("numerical_severity")

                total_overall_in_pt = Finding.objects.filter(date__lte=end_date,
                                                            false_p=False,
                                                            duplicate=False,
                                                            out_of_scope=False,
                                                            mitigated__isnull=True,
                                                            test__engagement__product__prod_type=pt,
                                                            severity__in=("Critical", "High", "Medium", "Low")).aggregate(
                    total=Sum(
                        Case(When(severity__in=("Critical", "High", "Medium", "Low"),
                                then=Value(1)),
                            output_field=IntegerField())))["total"]

                all_current_in_pt = Finding.objects.filter(date__lte=end_date,
                                                        false_p=False,
                                                        duplicate=False,
                                                        out_of_scope=False,
                                                        mitigated__isnull=True,
                                                        test__engagement__product__prod_type=pt,
                                                        severity__in=(
                                                            "Critical", "High", "Medium", "Low")).prefetch_related(
                    "test__engagement__product",
                    "test__engagement__product__prod_type",
                    "test__engagement__risk_acceptance",
                    "reporter").order_by(
                    "numerical_severity")

                top_ten = Product.objects.filter(engagement__test__finding__date__lte=end_date,
                                                engagement__test__finding__false_p=False,
                                                engagement__test__finding__duplicate=False,
                                                engagement__test__finding__out_of_scope=False,
                                                engagement__test__finding__mitigated__isnull=True,
                                                engagement__test__finding__severity__in=(
                                                    "Critical", "High", "Medium", "Low"),
                                                prod_type=pt)

            top_ten = severity_count(top_ten, "annotate", "engagement__test__finding__severity").order_by("-critical", "-high", "-medium", "-low")[:10]

            cip = {"S0": 0,
                   "S1": 0,
                   "S2": 0,
                   "S3": 0,
                   "Total": total_closed_in_period}

            aip = {"S0": 0,
                   "S1": 0,
                   "S2": 0,
                   "S3": 0,
                   "Total": total_overall_in_pt}

            for o in closed_in_period:
                cip[o["numerical_severity"]] = o["numerical_severity__count"]

            for o in overall_in_pt:
                aip[o["numerical_severity"]] = o["numerical_severity__count"]
        else:
            messages.add_message(request, messages.ERROR, _("Please choose month and year and the Product Type."),
                                 extra_tags="alert-danger")

    add_breadcrumb(title=_("Bi-Weekly Metrics"), top_level=True, request=request)

    return render(request,
                  "dojo/pt_counts.html",
                  {"form": form,
                   "start_date": start_date,
                   "end_date": end_date,
                   "opened_in_period": oip,
                   "trending_opened": opened_in_period_list,
                   "closed_in_period": cip,
                   "overall_in_pt": aip,
                   "all_current_in_pt": all_current_in_pt,
                   "top_ten": top_ten,
                   "pt": pt},
                  )


def product_tag_counts(request):
    form = ProductTagCountsForm()
    opened_in_period_list = []
    oip = None
    cip = None
    aip = None
    all_current_in_pt = None
    top_ten = None
    pt = None
    today = timezone.now()
    first_of_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    mid_month = first_of_month.replace(day=15, hour=23, minute=59, second=59, microsecond=999999)
    end_of_month = mid_month.replace(day=monthrange(today.year, today.month)[1], hour=23, minute=59, second=59,
                                     microsecond=999999)
    start_date = first_of_month
    end_date = end_of_month

    if request.method == "GET" and "month" in request.GET and "year" in request.GET and "product_tag" in request.GET:
        form = ProductTagCountsForm(request.GET)
        if form.is_valid():
            prods = get_authorized_products(Permissions.Product_View)

            pt = form.cleaned_data["product_tag"]
            month = int(form.cleaned_data["month"])
            year = int(form.cleaned_data["year"])
            first_of_month = first_of_month.replace(month=month, year=year)

            month_requested = datetime(year, month, 1)

            end_of_month = month_requested.replace(day=monthrange(month_requested.year, month_requested.month)[1],
                                                   hour=23, minute=59, second=59, microsecond=999999)
            start_date = first_of_month
            start_date = datetime(start_date.year,
                                  start_date.month, start_date.day,
                                  tzinfo=timezone.get_current_timezone())
            end_date = end_of_month
            end_date = datetime(end_date.year,
                                end_date.month, end_date.day,
                                tzinfo=timezone.get_current_timezone())

            oip = opened_in_period(start_date, end_date,
                test__engagement__product__tags__name=pt,
                test__engagement__product__in=prods)

            # trending data - 12 months
            opened_in_period_list.extend(opened_in_period(start_date + relativedelta(months=-x), end_of_month + relativedelta(months=-x),
                                     test__engagement__product__tags__name=pt, test__engagement__product__in=prods) for x in range(12, 0, -1))

            opened_in_period_list.append(oip)

            closed_in_period = Finding.objects.filter(mitigated__date__range=[start_date, end_date],
                                                      test__engagement__product__tags__name=pt,
                                                      test__engagement__product__in=prods,
                                                      severity__in=("Critical", "High", "Medium", "Low")).values(
                "numerical_severity").annotate(Count("numerical_severity")).order_by("numerical_severity")

            total_closed_in_period = Finding.objects.filter(mitigated__date__range=[start_date, end_date],
                                                            test__engagement__product__tags__name=pt,
                                                            test__engagement__product__in=prods,
                                                            severity__in=(
                                                                "Critical", "High", "Medium", "Low")).aggregate(
                total=Sum(
                    Case(When(severity__in=("Critical", "High", "Medium", "Low"),
                              then=Value(1)),
                         output_field=IntegerField())))["total"]

            if get_system_setting("enforce_verified_status", True) or get_system_setting("enforce_verified_status_metrics", True):
                overall_in_pt = Finding.objects.filter(date__lt=end_date,
                                                    verified=True,
                                                    false_p=False,
                                                    duplicate=False,
                                                    out_of_scope=False,
                                                    mitigated__isnull=True,
                                                    test__engagement__product__tags__name=pt,
                                                    test__engagement__product__in=prods,
                                                    severity__in=("Critical", "High", "Medium", "Low")).values(
                    "numerical_severity").annotate(Count("numerical_severity")).order_by("numerical_severity")

                total_overall_in_pt = Finding.objects.filter(date__lte=end_date,
                                                            verified=True,
                                                            false_p=False,
                                                            duplicate=False,
                                                            out_of_scope=False,
                                                            mitigated__isnull=True,
                                                            test__engagement__product__tags__name=pt,
                                                            test__engagement__product__in=prods,
                                                            severity__in=("Critical", "High", "Medium", "Low")).aggregate(
                    total=Sum(
                        Case(When(severity__in=("Critical", "High", "Medium", "Low"),
                                then=Value(1)),
                            output_field=IntegerField())))["total"]

                all_current_in_pt = Finding.objects.filter(date__lte=end_date,
                                                        verified=True,
                                                        false_p=False,
                                                        duplicate=False,
                                                        out_of_scope=False,
                                                        mitigated__isnull=True,
                                                        test__engagement__product__tags__name=pt,
                                                        test__engagement__product__in=prods,
                                                        severity__in=(
                                                            "Critical", "High", "Medium", "Low")).prefetch_related(
                    "test__engagement__product",
                    "test__engagement__product__prod_type",
                    "test__engagement__risk_acceptance",
                    "reporter").order_by(
                    "numerical_severity")

                top_ten = Product.objects.filter(engagement__test__finding__date__lte=end_date,
                                                engagement__test__finding__verified=True,
                                                engagement__test__finding__false_p=False,
                                                engagement__test__finding__duplicate=False,
                                                engagement__test__finding__out_of_scope=False,
                                                engagement__test__finding__mitigated__isnull=True,
                                                engagement__test__finding__severity__in=(
                                                    "Critical", "High", "Medium", "Low"),
                                                tags__name=pt, engagement__product__in=prods)
            else:
                overall_in_pt = Finding.objects.filter(date__lt=end_date,
                                                    false_p=False,
                                                    duplicate=False,
                                                    out_of_scope=False,
                                                    mitigated__isnull=True,
                                                    test__engagement__product__tags__name=pt,
                                                    test__engagement__product__in=prods,
                                                    severity__in=("Critical", "High", "Medium", "Low")).values(
                    "numerical_severity").annotate(Count("numerical_severity")).order_by("numerical_severity")

                total_overall_in_pt = Finding.objects.filter(date__lte=end_date,
                                                            false_p=False,
                                                            duplicate=False,
                                                            out_of_scope=False,
                                                            mitigated__isnull=True,
                                                            test__engagement__product__tags__name=pt,
                                                            test__engagement__product__in=prods,
                                                            severity__in=("Critical", "High", "Medium", "Low")).aggregate(
                    total=Sum(
                        Case(When(severity__in=("Critical", "High", "Medium", "Low"),
                                then=Value(1)),
                            output_field=IntegerField())))["total"]

                all_current_in_pt = Finding.objects.filter(date__lte=end_date,
                                                        false_p=False,
                                                        duplicate=False,
                                                        out_of_scope=False,
                                                        mitigated__isnull=True,
                                                        test__engagement__product__tags__name=pt,
                                                        test__engagement__product__in=prods,
                                                        severity__in=(
                                                            "Critical", "High", "Medium", "Low")).prefetch_related(
                    "test__engagement__product",
                    "test__engagement__product__prod_type",
                    "test__engagement__risk_acceptance",
                    "reporter").order_by(
                    "numerical_severity")

                top_ten = Product.objects.filter(engagement__test__finding__date__lte=end_date,
                                                engagement__test__finding__false_p=False,
                                                engagement__test__finding__duplicate=False,
                                                engagement__test__finding__out_of_scope=False,
                                                engagement__test__finding__mitigated__isnull=True,
                                                engagement__test__finding__severity__in=(
                                                    "Critical", "High", "Medium", "Low"),
                                                tags__name=pt, engagement__product__in=prods)

            top_ten = severity_count(top_ten, "annotate", "engagement__test__finding__severity").order_by("-critical", "-high", "-medium", "-low")[:10]

            cip = {"S0": 0,
                   "S1": 0,
                   "S2": 0,
                   "S3": 0,
                   "Total": total_closed_in_period}

            aip = {"S0": 0,
                   "S1": 0,
                   "S2": 0,
                   "S3": 0,
                   "Total": total_overall_in_pt}

            for o in closed_in_period:
                cip[o["numerical_severity"]] = o["numerical_severity__count"]

            for o in overall_in_pt:
                aip[o["numerical_severity"]] = o["numerical_severity__count"]
        else:
            messages.add_message(request, messages.ERROR, _("Please choose month and year and the Product Tag."),
                                 extra_tags="alert-danger")

    add_breadcrumb(title=_("Bi-Weekly Metrics"), top_level=True, request=request)

    return render(request,
                  "dojo/pt_counts.html",
                  {"form": form,
                   "start_date": start_date,
                   "end_date": end_date,
                   "opened_in_period": oip,
                   "trending_opened": opened_in_period_list,
                   "closed_in_period": cip,
                   "overall_in_pt": aip,
                   "all_current_in_pt": all_current_in_pt,
                   "top_ten": top_ten,
                   "pt": pt},
                  )


def engineer_metrics(request):
    # only superusers can select other users to view
    if request.user.is_superuser:
        users = Dojo_User.objects.all().order_by("username")
    else:
        return HttpResponseRedirect(reverse("view_engineer", args=(request.user.id,)))

    users = UserFilter(request.GET, queryset=users)
    paged_users = get_page_items(request, users.qs, 25)

    add_breadcrumb(title=_("Engineer Metrics"), top_level=True, request=request)

    return render(request,
                  "dojo/engineer_metrics.html",
                  {"users": paged_users,
                   "filtered": users,
                   })


"""
Greg
Status: in prod
indvidual view of engineer metrics for a given month. Only superusers,
and root can view others metrics
"""


@vary_on_cookie
def view_engineer(request, eid):
    user = get_object_or_404(Dojo_User, pk=eid)
    if not (request.user.is_superuser or request.user.username == user.username):
        raise PermissionDenied

    now = timezone.now()
    tz = now.tzinfo

    # ---------------
    # Base query-sets
    reporter_findings = Finding.objects.filter(reporter=user)
    if get_system_setting("enforce_verified_status", True) or get_system_setting(
        "enforce_verified_status_metrics", True,
    ):
        reporter_findings = reporter_findings.filter(verified=True)

    closed_findings = Finding.objects.filter(mitigated_by=user)
    open_findings = (
        reporter_findings.filter(mitigated__isnull=True)
        .select_related("test__engagement__product__prod_type", "reporter")
        .prefetch_related("risk_acceptance_set")
    )

    # --------------------
    # Month & week buckets
    month_start = datetime(now.year, now.month, 1, tzinfo=tz)
    month_end = month_start + relativedelta(months=1)  # first day of next month (exclusive)

    open_month = reporter_findings.filter(date__gte=month_start, date__lt=month_end)
    closed_month = closed_findings.filter(mitigated__gte=month_start, mitigated__lt=month_end)
    accepted_month = (
        Finding.objects.filter(
            risk_acceptance__owner=user,
            risk_acceptance__created__gte=month_start,
            risk_acceptance__created__lt=month_end,
        ).distinct()
    )

    week_start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    week_end = week_start + timedelta(days=7)  # next Monday 00:00 (exclusive)
    open_week = reporter_findings.filter(date__gte=week_start, date__lt=week_end)
    closed_week = closed_findings.filter(mitigated__gte=week_start, mitigated__lt=week_end)
    accepted_week = (
        Finding.objects.filter(
            risk_acceptance__owner=user,
            risk_acceptance__created__gte=week_start,
            risk_acceptance__created__lt=week_end,
        ).distinct()
    )

    o_dict, open_count = count_findings(open_month)
    c_dict, closed_count = count_findings(closed_month)
    a_dict, accepted_count = count_findings(accepted_month)
    o_week_dict, open_week_count = count_findings(open_week)
    c_week_dict, closed_week_count = count_findings(closed_week)
    a_week_dict, accepted_week_count = count_findings(accepted_week)

    # --------------------------
    # Historic series for charts
    monthly_total_series, monthly_open_series, monthly_accepted_series = [], [], []
    findings_this_period(reporter_findings, 1, monthly_total_series, monthly_open_series, monthly_accepted_series)

    weekly_total_series, weekly_open_series, weekly_accepted_series = [], [], []
    findings_this_period(reporter_findings, 0, weekly_total_series, weekly_open_series, weekly_accepted_series)

    ras_owner_qs = Risk_Acceptance.objects.filter(owner=user)
    _augment_series_with_accepted(monthly_accepted_series, ras_owner_qs, period="month", tz=tz)
    _augment_series_with_accepted(weekly_accepted_series, ras_owner_qs, period="week", tz=tz)

    chart_data = [["Date", "S0", "S1", "S2", "S3", "Total"], *monthly_open_series]
    a_chart_data = [["Date", "S0", "S1", "S2", "S3", "Total"], *monthly_accepted_series]
    week_chart_data = [["Date", "S0", "S1", "S2", "S3", "Total"], *weekly_open_series]
    week_a_chart_data = [["Date", "S0", "S1", "S2", "S3", "Total"], *weekly_accepted_series]

    # --------------
    # Product tables
    products = list(get_authorized_products(Permissions.Product_Type_View).only("id", "name"))
    update, total_update = _product_stats(products)

    # ----------------------------------
    # Age buckets for open critical/high
    high_crit_open = reporter_findings.filter(
        mitigated__isnull=True,
        active=True,
        risk_acceptance=None,
        severity__in=["Critical", "High"],
    )
    age_buckets = _age_buckets(high_crit_open)

    # -------------
    # Details table
    details = sorted(
        (
            [
                f.test.engagement.product.prod_type.name,
                f.test.engagement.product.name,
                f.severity,
                f.title,
                (date.today() - f.date).days,
                "Accepted" if f.risk_accepted else "Active",
                f.reporter,
            ]
            for f in open_findings
        ),
        key=operator.itemgetter(2),
    )

    add_breadcrumb(title=f"{user.get_full_name()} Metrics", top_level=False, request=request)

    return render(
        request,
        "dojo/view_engineer.html",
        {
            # month
            "open_month": open_month,
            "a_month": accepted_month,
            "low_a_month": accepted_count["low"],
            "medium_a_month": accepted_count["med"],
            "high_a_month": accepted_count["high"],
            "critical_a_month": accepted_count["crit"],
            "closed_month": closed_month,
            "low_open_month": open_count["low"],
            "medium_open_month": open_count["med"],
            "high_open_month": open_count["high"],
            "critical_open_month": open_count["crit"],
            "low_c_month": closed_count["low"],
            "medium_c_month": closed_count["med"],
            "high_c_month": closed_count["high"],
            "critical_c_month": closed_count["crit"],
            # week
            "week_stuff": weekly_total_series,
            "week_a_stuff": weekly_accepted_series,
            # series
            "a_total": monthly_accepted_series,
            "total": monthly_total_series,
            "sub": len(monthly_total_series),
            # product tables
            "update": update,
            "total_update": total_update,
            # aged buckets
            "lt": age_buckets["lt"],
            "ls": age_buckets["ls"],
            "ln": age_buckets["ln"],
            "mn": age_buckets["mn"],
            # charts
            "chart_data": chart_data,
            "a_chart_data": a_chart_data,
            "week_chart_data": week_chart_data,
            "week_a_chart_data": week_a_chart_data,
            # misc
            "name": f"{user.get_full_name()} Metrics",
            "metric": True,
            "details": details,
            "open_week": open_week,
            "closed_week": closed_week,
            "accepted_week": accepted_week,
            "a_dict": a_dict,
            "o_dict": o_dict,
            "c_dict": c_dict,
            "o_week_dict": o_week_dict,
            "a_week_dict": a_week_dict,
            "c_week_dict": c_week_dict,
            "open_week_count": open_week_count,
            "accepted_week_count": accepted_week_count,
            "closed_week_count": closed_week_count,
            "user": request.user,
        },
    )


def _age_buckets(qs):
    """Return aged high/critical finding counts in one SQL round-trip."""
    today = date.today()
    return qs.aggregate(
        lt=Count("id", filter=Q(date__gte=today - timedelta(days=30))),
        ls=Count("id", filter=Q(date__lte=today - timedelta(days=30), date__gt=today - timedelta(days=60))),
        ln=Count("id", filter=Q(date__lte=today - timedelta(days=60), date__gt=today - timedelta(days=90))),
        mn=Count("id", filter=Q(date__lte=today - timedelta(days=90))),
    )


def _augment_series_with_accepted(series: list[list], ras_qs, *, period: str, tz):
    """Mutate `series` in-place, adding per-severity counts for accepted findings."""
    if not series:  # no buckets to augment
        return

    first_ra = ras_qs.first()
    if first_ra is None:  # engineer has no risk acceptances at all
        return

    owner = first_ra.owner
    sev_idx = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}

    for bucket in series:
        if period == "month":
            start = datetime.strptime(bucket[0].strip(), "%b %Y").replace(tzinfo=tz)
            end = start + relativedelta(months=1)  # first day of next month (exclusive)
        else:  # "week"
            wk_a, _ = (d.strip() for d in bucket[0].split("-"))
            year = timezone.now().year
            start = datetime.strptime(f"{wk_a} {year}", "%b %d %Y").replace(tzinfo=tz)
            end = start + timedelta(days=7)  # next Monday 00:00 (exclusive)

        accepted = (
            Finding.objects.filter(
                risk_acceptance__owner=owner,
                risk_acceptance__created__gte=start,
                risk_acceptance__created__lt=end,
            )
            .values("severity")
            .annotate(cnt=Count("id"))
        )

        for row in accepted:
            bucket[sev_idx[row["severity"]]] += row["cnt"]

        bucket[5] = sum(bucket[1:])


def _product_stats(products) -> tuple[list, list]:
    """
    Return two tables:
    * `update` - top-10 products by open findings
    * `total_update` - all authorized products
    """
    counts = (
        Finding.objects.filter(test__engagement__product__in=products, mitigated__isnull=True, active=True)
        .values(pid=F("test__engagement__product"))
        .annotate(
            critical=Count("id", filter=Q(severity="Critical")),
            high=Count("id", filter=Q(severity="High")),
            medium=Count("id", filter=Q(severity="Medium")),
            low=Count("id", filter=Q(severity="Low")),
            total=Count("id"),
        )
    )
    by_id = {c["pid"]: c for c in counts}
    top10 = sorted(by_id.items(), key=lambda kv: kv[1]["total"], reverse=True)[:10]

    product_lookup = {p.id: p for p in products}

    def row(prod_id):
        prod = product_lookup[prod_id]
        link = f"<a href='{reverse('product_open_findings', args=(prod.id,))}'>{escape(prod.name)}</a>"
        data = by_id[prod_id]
        return [link, data["critical"], data["high"], data["medium"], data["low"], data["total"]]

    update = [row(pid) for pid, _ in top10]
    total_update = [row(p.id) for p in products if p.id in by_id]

    return update, total_update
