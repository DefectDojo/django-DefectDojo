from django.db.models import Count, Q
from django.shortcuts import render
from dojo.models import Component
from dojo.authorization.roles_permissions import Permissions
from dojo.filters import ComponentFilter, ComponentFilterWithoutObjectLookups
from dojo.product.queries import get_authorized_products
from dojo.utils import add_breadcrumb, get_system_setting
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from collections import defaultdict

def components(request):
    add_breadcrumb(title="Components", top_level=True, request=request)
    
    # Obtain authorized products
    authorized_products = get_authorized_products(Permissions.Product_View, request.user)

    # Filter components whose engagement belongs to an authorized product and notes the desired columns
    component_query = Component.objects.filter(engagement__product__in=authorized_products).select_related("engagement__product")
    
    # Add annotations to count findings
    component_query = component_query.annotate(
        total_findings=Count('finding__id', distinct=True), 
        active_findings=Count('finding__id', filter=Q(finding__active=True), distinct=True),
        closed_findings=Count('finding__id', filter=Q(finding__is_mitigated=True), distinct=True)
    )

    # Order by total findings
    component_query = component_query.order_by("-total_findings")

    # Apply filters
    filter_string_matching = get_system_setting("filter_string_matching", False)
    filter_class = ComponentFilterWithoutObjectLookups if filter_string_matching else ComponentFilter
    comp_filter = filter_class(request.GET, queryset=component_query)


    # Groups all components by product and, additionally, groups those where (name, version) are equal
    grouped = defaultdict(lambda: defaultdict(lambda: {"active_findings": 0, "closed_findings": 0, "total_findings": 0, "comps": []}))

    for comp in comp_filter.qs:
        product = comp.engagement.product
        key = (comp.name, comp.version)
        group = grouped[product][key]

        group["active_findings"] += comp.active_findings
        group["closed_findings"] += comp.closed_findings
        group["total_findings"] += comp.total_findings
        group["comps"].append(comp)

    # Convert the grouped structure to a list for pagination
    aggregated_list = [
        {
            "product": product,
            "name": comp_name,
            "version": comp_version,
            "active_findings": data["active_findings"],
            "closed_findings": data["closed_findings"],
            "total_findings": data["total_findings"],
            "id": data["comps"][0].id
        }
        for product, groups in grouped.items()
        for (comp_name, comp_version), data in groups.items()
    ]
    # Now we apply the pagination on the aggregated list
    page_size = request.GET.get("page_size", "25")
    try:
        page_size = int(page_size)
        if page_size <= 0:
            page_size = 25
    except ValueError:
        page_size = 25


    paginator = Paginator(aggregated_list, page_size)
    page = request.GET.get("page")
    try:
        aggregated_page = paginator.page(page)
    except PageNotAnInteger:
        aggregated_page = paginator.page(1)
    except EmptyPage:
        aggregated_page = paginator.page(paginator.num_pages)

    # Autocomplete component names
    component_words = component_query.exclude(name__isnull=True).values_list("name", flat=True)

    return render(
        request,
        "dojo/components.html",
        {
            "filter": comp_filter,
            "page_obj": aggregated_page,
            "component_words": sorted(set(component_words)),
            "enable_table_filtering": get_system_setting("enable_ui_table_based_searching"),
        },
    )