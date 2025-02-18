# #  metrics
import collections
import logging
import operator
from calendar import monthrange
from collections import OrderedDict
from datetime import date, datetime, timedelta
from functools import reduce
from operator import itemgetter

from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.db.models import Case, Count, IntegerField, Q, Sum, Value, When
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.utils.html import escape
from django.utils.translation import gettext as _
from django.views.decorators.cache import cache_page
from django.views.decorators.vary import vary_on_cookie

from dojo.authorization.authorization import user_has_permission_or_403
from dojo.authorization.authorization_decorators import user_has_role_permission
from dojo.authorization.roles_permissions import Permissions, Roles
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
from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Risk_Acceptance, Role, Test
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


@cache_page(60 * 15)  # cache for 15 minutes
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
        total_closed = []
        total_opened = []
        findings_broken_out = {}

        total = Finding.objects.filter(test__engagement__product__prod_type=pt,
                                       false_p=False,
                                       duplicate=False,
                                       out_of_scope=False,
                                       date__month=now.month,
                                       date__year=now.year,
                                       )

        if get_system_setting("enforce_verified_status", True):
            total = total.filter(verified=True)

        total = total.distinct()

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

            if f.mitigated and f.mitigated.year == now.year and f.mitigated.month == now.month:
                total_closed.append(f)

            if f.date.year == now.year and f.date.month == now.month:
                total_opened.append(f)

        findings_broken_out["Total"] = len(total)
        findings_broken_out["S0"] = len(total_critical)
        findings_broken_out["S1"] = len(total_high)
        findings_broken_out["S2"] = len(total_medium)
        findings_broken_out["S3"] = len(total_low)
        findings_broken_out["S4"] = len(total_info)

        findings_broken_out["Opened"] = len(total_opened)
        findings_broken_out["Closed"] = len(total_closed)

        findings_by_product_type[pt] = findings_broken_out

    add_breadcrumb(title=page_name, top_level=True, request=request)

    return render(request, "dojo/simple_metrics.html", {
        "findings": findings_by_product_type,
        "name": page_name,
        "metric": True,
        "user": request.user,
        "form": form,
    })

# @cache_page(60 * 15)  # cache for 15 minutes
# @vary_on_cookie
def metrics_panel(request):
    page_name = _('Metrics Panel')
    now = timezone.now()
    role = Role.objects.get(id=Roles.Maintainer)
    user = request.user.id
    cookie_csrftoken = request.COOKIES.get('csrftoken', '')
    cookie_sessionid = request.COOKIES.get('sessionid', '')
    grafana_params = f"{settings.GRAFANA_PARAMS}&var-csrftoken={cookie_csrftoken}&var-sessionid={cookie_sessionid}"
    add_breadcrumb(title=page_name, top_level=not len(request.GET), request=request)
    return render(request, 'dojo/metrics_panel.html', {
       'name': page_name,
       'grafana_url': settings.GRAFANA_URL,
       'grafana_path': settings.GRAFANA_PATH.get("metrics_panel"),
       'grafana_params': grafana_params,
       'role': role,
       'user': user,
    })

@user_has_role_permission(Permissions.Metrics_DevSecOps)
def metrics_devsecops(request):
    page_name = _('Metrics DevSecOps')
    role = Role.objects.get(id=Roles.Maintainer)
    user = request.user.id
    add_breadcrumb(title=page_name, top_level=not len(request.GET), request=request)
    return render(request, 'dojo/metrics_devsecops.html', {
       'name': page_name,
       'grafana_url': settings.GRAFANA_URL,
       'grafana_path': settings.GRAFANA_PATH.get("metrics_devsecops"),
       'grafana_params': settings.GRAFANA_PARAMS,
       'role': role,
       'user': user,
    })

@user_has_role_permission(Permissions.Metrics_Panel_Admin)
def metrics_panel_admin(request):
    page_name = _('Metrics Panel Admin')
    role = Role.objects.get(id=Roles.Maintainer)
    user = request.user.id
    cookie_csrftoken = request.COOKIES.get('csrftoken', '')
    cookie_sessionid = request.COOKIES.get('sessionid', '')
    grafana_params = f"{settings.GRAFANA_PARAMS}&var-csrftoken={cookie_csrftoken}&var-sessionid={cookie_sessionid}"
    add_breadcrumb(title=page_name, top_level=not len(request.GET), request=request)
    return render(request, 'dojo/metrics_panel_admin.html', {
       'name': page_name,
       'grafana_url': settings.GRAFANA_URL,
       'grafana_path': settings.GRAFANA_PATH.get("metrics_panel_admin"),
       'grafana_params': grafana_params,
       'role': role,
       'user': user,
    })
    
@user_has_role_permission(Permissions.Metrics_Vultracker)    
def metrics_vultracker(request):
    page_name = _('Metrics Vultracker')
    role = Role.objects.get(id=Roles.Maintainer)
    user = request.user.id
    cookie_csrftoken = request.COOKIES.get('csrftoken', '')
    cookie_sessionid = request.COOKIES.get('sessionid', '')
    mf_vultracker_params = f"?csrftoken={cookie_csrftoken}&sessionid={cookie_sessionid}"
    add_breadcrumb(title=page_name, top_level=not len(request.GET), request=request)
    return render(request, 'dojo/metrics_vultracker.html', {
       'name': page_name,
       'mf_vultracker_url': settings.MF_VULTRACKER_URL,
       'mf_vultracker_path': settings.MF_VULTRACKER_PATH.get("metrics_vultracker"),
       'mf_vultracker_params': mf_vultracker_params,
       'role': role,
       'user': user,
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
            for x in range(12, 0, -1):
                opened_in_period_list.append(
                    opened_in_period(start_date + relativedelta(months=-x), end_of_month + relativedelta(months=-x),
                                     test__engagement__product__prod_type=pt))

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

            if get_system_setting("enforce_verified_status", True):
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
            for x in range(12, 0, -1):
                opened_in_period_list.append(
                    opened_in_period(start_date + relativedelta(months=-x), end_of_month + relativedelta(months=-x),
                                     test__engagement__product__tags__name=pt, test__engagement__product__in=prods))

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

            if get_system_setting("enforce_verified_status", True):
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


# noinspection DjangoOrm
@cache_page(60 * 5)  # cache for 5 minutes
@vary_on_cookie
def view_engineer(request, eid):
    user = get_object_or_404(Dojo_User, pk=eid)
    if not (request.user.is_superuser
            or request.user.username == user.username):
        raise PermissionDenied
    now = timezone.now()

    if get_system_setting("enforce_verified_status", True):
        findings = Finding.objects.filter(reporter=user, verified=True)
    else:
        findings = Finding.objects.filter(reporter=user)

    closed_findings = Finding.objects.filter(mitigated_by=user)
    open_findings = findings.exclude(mitigated__isnull=False)
    open_month = findings.filter(date__year=now.year, date__month=now.month)
    accepted_month = [finding for ra in Risk_Acceptance.objects.filter(
        created__range=[datetime(now.year,
                                 now.month, 1,
                                 tzinfo=timezone.get_current_timezone()),
                        datetime(now.year,
                                 now.month,
                                 monthrange(now.year,
                                            now.month)[1],
                                 tzinfo=timezone.get_current_timezone())],
        owner=user)
                      for finding in ra.accepted_findings.all()]
    closed_month = []
    for f in closed_findings:
        if f.mitigated and f.mitigated.year == now.year and f.mitigated.month == now.month:
            closed_month.append(f)

    o_dict, open_count = count_findings(open_month)
    c_dict, closed_count = count_findings(closed_month)
    a_dict, accepted_count = count_findings(accepted_month)
    day_list = [now - relativedelta(weeks=1,
                                    weekday=x,
                                    hour=0,
                                    minute=0,
                                    second=0)
                for x in range(now.weekday())]
    day_list.append(now)

    q_objects = (Q(date=d) for d in day_list)
    closed_week = []
    open_week = findings.filter(reduce(operator.or_, q_objects))

    accepted_week = [finding for ra in Risk_Acceptance.objects.filter(
        owner=user, created__range=[day_list[0], day_list[-1]])
                     for finding in ra.accepted_findings.all()]

    q_objects = (Q(mitigated=d) for d in day_list)
    # closed_week= findings.filter(reduce(operator.or_, q_objects))
    for f in closed_findings:
        if f.mitigated and f.mitigated >= day_list[0]:
            closed_week.append(f)

    o_week_dict, open_week_count = count_findings(open_week)
    c_week_dict, closed_week_count = count_findings(closed_week)
    a_week_dict, accepted_week_count = count_findings(accepted_week)

    stuff = []
    o_stuff = []
    a_stuff = []
    findings_this_period(findings, 1, stuff, o_stuff, a_stuff)
    # findings_this_period no longer fits the need for accepted findings
    # however will use its week finding output to use here
    for month in a_stuff:
        month_start = datetime.strptime(
            month[0].strip(), "%b %Y")
        month_end = datetime(month_start.year,
                             month_start.month,
                             monthrange(
                                 month_start.year,
                                 month_start.month)[1],
                             tzinfo=timezone.get_current_timezone())
        for finding in [finding for ra in Risk_Acceptance.objects.filter(
                created__range=[month_start, month_end], owner=user)
                        for finding in ra.accepted_findings.all()]:
            if finding.severity == "Critical":
                month[1] += 1
            if finding.severity == "High":
                month[2] += 1
            if finding.severity == "Medium":
                month[3] += 1
            if finding.severity == "Low":
                month[4] += 1

        month[5] = sum(month[1:])
    week_stuff = []
    week_o_stuff = []
    week_a_stuff = []
    findings_this_period(findings, 0, week_stuff, week_o_stuff, week_a_stuff)

    # findings_this_period no longer fits the need for accepted findings
    # however will use its week finding output to use here
    for week in week_a_stuff:
        wk_range = week[0].split("-")
        week_start = datetime.strptime(
            wk_range[0].strip() + " " + str(now.year), "%b %d %Y")
        week_end = datetime.strptime(
            wk_range[1].strip() + " " + str(now.year), "%b %d %Y")

        for finding in [finding for ra in Risk_Acceptance.objects.filter(
                created__range=[week_start, week_end], owner=user)
                        for finding in ra.accepted_findings.all()]:
            if finding.severity == "Critical":
                week[1] += 1
            if finding.severity == "High":
                week[2] += 1
            if finding.severity == "Medium":
                week[3] += 1
            if finding.severity == "Low":
                week[4] += 1

        week[5] = sum(week[1:])

    products = get_authorized_products(Permissions.Product_Type_View)
    vulns = {}
    for product in products:
        f_count = 0
        engs = Engagement.objects.filter(product=product)
        for eng in engs:
            tests = Test.objects.filter(engagement=eng)
            for test in tests:
                f_count += findings.filter(test=test,
                                           mitigated__isnull=True,
                                           active=True).count()
        vulns[product.id] = f_count
    od = OrderedDict(sorted(vulns.items(), key=itemgetter(1)))
    items = list(od.items())
    items.reverse()
    top = items[: 10]
    update = []
    for t in top:
        product = t[0]
        z_count = 0
        o_count = 0
        t_count = 0
        h_count = 0
        engs = Engagement.objects.filter(
            product=Product.objects.get(id=product))
        for eng in engs:
            tests = Test.objects.filter(engagement=eng)
            for test in tests:
                z_count += findings.filter(
                    test=test,
                    mitigated__isnull=True,
                    severity="Critical",
                ).count()
                o_count += findings.filter(
                    test=test,
                    mitigated__isnull=True,
                    severity="High",
                ).count()
                t_count += findings.filter(
                    test=test,
                    mitigated__isnull=True,
                    severity="Medium",
                ).count()
                h_count += findings.filter(
                    test=test,
                    mitigated__isnull=True,
                    severity="Low",
                ).count()
        prod = Product.objects.get(id=product)
        all_findings_link = "<a href='{}'>{}</a>".format(
            reverse("product_open_findings", args=(prod.id,)), escape(prod.name))
        update.append([all_findings_link, z_count, o_count, t_count, h_count,
                       z_count + o_count + t_count + h_count])
    total_update = []
    for i in items:
        product = i[0]
        z_count = 0
        o_count = 0
        t_count = 0
        h_count = 0
        engs = Engagement.objects.filter(
            product=Product.objects.get(id=product))
        for eng in engs:
            tests = Test.objects.filter(engagement=eng)
            for test in tests:
                z_count += findings.filter(
                    test=test,
                    mitigated__isnull=True,
                    severity="Critical").count()
                o_count += findings.filter(
                    test=test,
                    mitigated__isnull=True,
                    severity="High").count()
                t_count += findings.filter(
                    test=test,
                    mitigated__isnull=True,
                    severity="Medium").count()
                h_count += findings.filter(
                    test=test,
                    mitigated__isnull=True,
                    severity="Low").count()
        prod = Product.objects.get(id=product)
        all_findings_link = "<a href='{}'>{}</a>".format(
            reverse("product_open_findings", args=(prod.id,)), escape(prod.name))
        total_update.append([all_findings_link, z_count, o_count, t_count,
                             h_count, z_count + o_count + t_count + h_count])

    neg_length = len(stuff)
    findz = findings.filter(mitigated__isnull=True, active=True,
                            risk_acceptance=None)
    findz = findz.filter(Q(severity="Critical") | Q(severity="High"))
    less_thirty = 0
    less_sixty = 0
    less_nine = 0
    more_nine = 0
    for finding in findz:
        elapsed = date.today() - finding.date
        if elapsed <= timedelta(days=30):
            less_thirty += 1
        elif elapsed <= timedelta(days=60):
            less_sixty += 1
        elif elapsed <= timedelta(days=90):
            less_nine += 1
        else:
            more_nine += 1

    # Data for the monthly charts
    chart_data = [["Date", "S0", "S1", "S2", "S3", "Total"]]
    for thing in o_stuff:
        chart_data.insert(1, thing)

    a_chart_data = [["Date", "S0", "S1", "S2", "S3", "Total"]]
    for thing in a_stuff:
        a_chart_data.insert(1, thing)

    # Data for the weekly charts
    week_chart_data = [["Date", "S0", "S1", "S2", "S3", "Total"]]
    for thing in week_o_stuff:
        week_chart_data.insert(1, thing)

    week_a_chart_data = [["Date", "S0", "S1", "S2", "S3", "Total"]]
    for thing in week_a_stuff:
        week_a_chart_data.insert(1, thing)

    details = []
    for find in open_findings:
        team = find.test.engagement.product.prod_type.name
        name = find.test.engagement.product.name
        severity = find.severity
        description = find.title
        life = date.today() - find.date
        life = life.days
        status = "Active"
        if find.risk_accepted:
            status = "Accepted"
        detail = [team, name, severity, description, life, status, find.reporter]
        details.append(detail)

    details = sorted(details, key=itemgetter(2))

    add_breadcrumb(title=f"{user.get_full_name()} Metrics", top_level=False, request=request)

    return render(request, "dojo/view_engineer.html", {
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
        "week_stuff": week_stuff,
        "week_a_stuff": week_a_stuff,
        "a_total": a_stuff,
        "total": stuff,
        "sub": neg_length,
        "update": update,
        "lt": less_thirty,
        "ls": less_sixty,
        "ln": less_nine,
        "mn": more_nine,
        "chart_data": chart_data,
        "a_chart_data": a_chart_data,
        "week_chart_data": week_chart_data,
        "week_a_chart_data": week_a_chart_data,
        "name": f"{user.get_full_name()} Metrics",
        "metric": True,
        "total_update": total_update,
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
    })
