from django.db.models import Count, Q, F
from django.shortcuts import render
from dojo.models import Component
from dojo.authorization.roles_permissions import Permissions
from dojo.filters import ComponentFilter, ComponentFilterWithoutObjectLookups
from dojo.engagement.queries import get_authorized_engagements
from dojo.utils import add_breadcrumb, get_page_items, get_system_setting

def components(request):
    add_breadcrumb(title="Components", top_level=True, request=request)
    
    # Obtain authorized engagements
    authorized_engagements = get_authorized_engagements(Permissions.Engagement_View)

    # Filter components based in authorized engagements
    component_query = Component.objects.filter(engagement__in=authorized_engagements).select_related("engagement__product", "engagement__product__prod_type")
    
    # Add annotations to count findings
    component_query = component_query.annotate(
        total_findings=Count('finding__id', distinct=True), 
        active_findings=Count('finding__id', filter=Q(finding__active=True), distinct=True),
        closed_findings=Count('finding__id', filter=Q(finding__is_mitigated=True), distinct=True),
        engagement_name=F('engagement__name'),
        product_name=F('engagement__product__name'),
        product_type_name=F('engagement__product__prod_type__name')
    )

    # Order by total findings
    component_query = component_query.order_by("-total_findings")

    # Apply filters
    filter_string_matching = get_system_setting("filter_string_matching", False)
    filter_class = ComponentFilterWithoutObjectLookups if filter_string_matching else ComponentFilter
    comp_filter = filter_class(request.GET, queryset=component_query)

    result = get_page_items(request, comp_filter.qs, 25)

    # Autocomplete component names
    component_words = component_query.exclude(name__isnull=True).values_list("name", flat=True)

    return render(
        request,
        "dojo/components.html",
        {
            "filter": comp_filter,
            "result": result,
            "component_words": sorted(set(component_words)),
            "enable_table_filtering": get_system_setting("enable_ui_table_based_searching"),
        },
    )