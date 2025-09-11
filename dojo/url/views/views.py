import logging
from datetime import datetime

from dateutil.relativedelta import relativedelta
from django.apps import apps
from django.conf import settings
from django.contrib import messages
from django.contrib.admin.utils import NestedObjects
from django.core.exceptions import PermissionDenied
from django.db import DEFAULT_DB_ALIAS
from django.db.models import OuterRef, QuerySet, Value
from django.db.models.functions import Coalesce
from django.http import HttpResponseRedirect, HttpRequest
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.db.models import Case, CharField, Count, F, Q, Value, When, IntegerField, Window, OuterRef, Subquery, Func
from django.db.models.functions import Coalesce
from dojo.authorization.authorization import user_has_permission_or_403
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions
from dojo.endpoint.queries import get_authorized_endpoints
from dojo.endpoint.utils import clean_hosts_run, endpoint_meta_import
from dojo.filters import EndpointFilter, EndpointFilterWithoutObjectLookups
from dojo.forms import AddEndpointForm, DeleteEndpointForm, DojoMetaDataForm, EditEndpointForm, ImportEndpointMetaForm
from dojo.models import DojoMeta, Endpoint, Endpoint_Status, Finding, Product
from dojo.query_utils import build_count_subquery
from dojo.utils import (
    Product_Tab,
    add_breadcrumb,
    add_error_message_to_response,
    calculate_grade,
    get_page_items,
    get_period_counts,
    get_setting,
    get_system_setting,
    is_scan_file_too_large,
    redirect,
)

logger = logging.getLogger(__name__)


from dojo.decorators import require_v3_feature_set
from dojo.url.models import URL
from dojo.url.filters import URLFilter
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus


@user_is_authorized(Endpoint, Permissions.Location_View, "location_id")
def view_endpoint(request: HttpRequest, location_id: int):
    return process_endpoint_view(request, location_id, host_view=False)


@user_is_authorized(Endpoint, Permissions.Location_View, "location_id")
def view_endpoint_host(request: HttpRequest, location_id: int):
    return process_endpoint_view(request, location_id, host_view=True)


def all_endpoints(request):
    return process_endpoints_view(request, host_view=False, vulnerable=False)


def all_endpoint_hosts(request):
    return process_endpoints_view(request, host_view=True, vulnerable=False)


def vulnerable_endpoints(request):
    return process_endpoints_view(request, host_view=False, vulnerable=True)


def vulnerable_endpoint_hosts(request):
    return process_endpoints_view(request, host_view=True, vulnerable=True)


def annotate_host_contents(queryset: QuerySet[Location]) -> QuerySet[Location]:
    """This essentially replaces the `overall_status` annotation helper on the manager class"""
    # Pre-aggregate all findings per host (once)
    finding_host_counts = (
        LocationFindingReference.objects.prefetch_related("location__url")
        .filter(location__url__host=OuterRef("url__host"))
        .values("location__url__host")
        .annotate(
            total_findings=Count("finding_id", distinct=True),
            active_findings=Count(
                "finding_id",
                filter=Q(status=FindingLocationStatus.Active),
                distinct=True,
            ),
        )
        .order_by("location__url__host")
    )
    product_host_counts = (
        LocationProductReference.objects.prefetch_related("location__url")
        .filter(location__url__host=OuterRef("url__host"))
        .values("location__url__host")
        .annotate(
            total_products=Count("product_id", distinct=True),
            active_products=Count(
                "product_id",
                filter=Q(status=ProductLocationStatus.Active),
                distinct=True,
            ),
        )
        .order_by("location__url__host")
    )

    return queryset.prefetch_related("url").annotate(
        host=Coalesce(F("url__host"), Value("", output_field=CharField())),
        total_findings=Subquery(finding_host_counts.values("total_findings")[:1]),
        active_findings=Subquery(finding_host_counts.values("active_findings")[:1]),
        total_products=Subquery(product_host_counts.values("total_products")[:1]),
        active_products=Subquery(product_host_counts.values("active_products")[:1]),
        mitigated_findings=F("total_findings") - F("active_findings"),
        overall_status=Case(
            When(
                Q(active_products__gt=0) | Q(active_findings__gt=0),
                then=Value(ProductLocationStatus.Active),
            ),
            default=Value(ProductLocationStatus.Mitigated),
            output_field=CharField(),
        ),
    )


def process_endpoint_view(request: HttpRequest, location_id: int, *, host_view=False):
    location = get_object_or_404(Location, id=location_id)
    host = location.url.host
    status = "No relationships defined"
    base_findings = Finding.objects.only(
        "id",
        "title",
        "severity",
        "epss_score",
        "epss_percentile",
        "date",
        "found_by",
        "active",
        "out_of_scope",
        "mitigated",
        "false_p",
        "duplicate",
        "found_by",
    ).prefetch_related("locations__location", "found_by")

    if host_view:
        base_locations = Location.objects.prefetch_related("tags", "url").filter(
            location_type=URL.LOCATION_TYPE, url__host=host
        )
        location_count = base_locations.count()
        locations = annotate_host_contents(
            get_authorized_endpoints(
                permission=Permissions.Location_View,
                queryset=base_locations,
                user=request.user,
            )
        )
        mitigated_location_count = locations.filter(overall_status=ProductLocationStatus.Mitigated).count()
        all_findings = base_findings.filter(
            locations__location__id__in=locations.values_list("id", flat=True)
        ).distinct()
    else:
        locations = None
        location_count = 0
        mitigated_location_count = 0
        all_findings = base_findings.filter(locations__location=location).distinct()

    active_findings = all_findings.filter(locations__status=FindingLocationStatus.Active).order_by("numerical_severity")

    if all_findings:
        start_date = timezone.make_aware(datetime.combine(all_findings.last().date, datetime.min.time()))
    else:
        start_date = timezone.now()
    end_date = timezone.now()

    relative_time = relativedelta(end_date, start_date)
    months_between = (relative_time.years * 12) + relative_time.months
    # include current month
    months_between += 1
    # closed_findings is needed as a parameter for get_periods_counts, but they are not relevant in the endpoint view
    closed_findings = Finding.objects.none()
    monthly_counts = get_period_counts(
        all_findings,
        closed_findings,
        None,
        months_between,
        start_date,
        relative_delta="months",
    )
    paged_findings = get_page_items(request, active_findings, 25)

    product_tab = None
    if "product" in request.GET:
        product = request.GET.getlist("product", [])
        if len(product) == 1:
            product = get_object_or_404(Product, id=product[0])
            user_has_permission_or_403(request.user, product, Permissions.Product_View)
            product_tab = Product_Tab(product, "Host" if host_view else "Endpoint", tab="endpoints")
            status = location.status_from_product(product)

    return render(
        request,
        "dojo/url/view.html",
        {
            "location": location,
            "locations": locations,
            "host": host,
            "product_tab": product_tab,
            "findings": paged_findings,
            "all_findings": all_findings,
            "active_findings_count": active_findings.count(),
            "all_findings_count": all_findings.count(),
            "opened_per_month": monthly_counts["opened_per_period"],
            "status": status,
            "host_view": host_view,
        },
    )


def process_endpoints_view(request, *, host_view=False, vulnerable=False):
    # First get the locations by status
    view_name = "Vulnerable" if vulnerable else "All"
    locations = get_authorized_endpoints(
        permission=Permissions.Location_View,
        queryset=Location.objects.prefetch_related("tags", "url").filter(location_type=URL.LOCATION_TYPE),
        user=request.user,
    )
    # Filter by active/vulnerable if requested
    if vulnerable:
        locations = locations.filter(products__status=ProductLocationStatus.Active)
    # Now apply the host/endpoint view specific filtering
    if host_view:
        view_name += " Hosts"
        locations = URLFilter(
            request.GET,
            queryset=annotate_host_contents(locations.order_by("url__host").distinct("url__host")),
            user=request.user,
        )
        location_count = locations.qs.count()
        mitigated_location_count = locations.qs.filter(overall_status=ProductLocationStatus.Mitigated).count()
    else:
        view_name += " Endpoints"
        locations = URLFilter(request.GET, queryset=locations.overall_status(), user=request.user)
        location_count = 0
        mitigated_location_count = 0
    # Do the pagination
    paged_locations = get_page_items(request, locations.qs, 25)
    # Add the breadcrumb
    add_breadcrumb(title=view_name, top_level=not len(request.GET), request=request)
    # Add the product tab if we are filtering by a single product
    product_tab = None
    if "product" in request.GET:
        products = request.GET.getlist("product", [])
        if len(products) == 1:
            product = get_object_or_404(Product, id=products[0])
            user_has_permission_or_403(request.user, product, Permissions.Product_View)
            product_tab = Product_Tab(product, view_name, tab="endpoints")

    return render(
        request,
        "dojo/url/list.html",
        {
            "product_tab": product_tab,
            "locations": paged_locations,
            "filtered": locations,
            "location_count": location_count,
            "mitigated_location_count": mitigated_location_count,
            "name": view_name,
            "host_view": host_view,
        },
    )
