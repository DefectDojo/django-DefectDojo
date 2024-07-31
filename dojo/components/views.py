from django.contrib.postgres.aggregates import StringAgg
from django.db import connection
from django.db.models import Count, Q
from django.db.models.expressions import Value
from django.shortcuts import render

from dojo.authorization.roles_permissions import Permissions
from dojo.components.sql_group_concat import Sql_GroupConcat
from dojo.filters import ComponentFilter, ComponentFilterWithoutObjectLookups
from dojo.finding.queries import get_authorized_findings
from dojo.utils import add_breadcrumb, get_page_items, get_system_setting


def components(request):
    add_breadcrumb(title="Components", top_level=True, request=request)
    separator = ", "
    # Get components ordered by component_name and concat component versions
    # to the same row

    component_query = get_authorized_findings(Permissions.Finding_View)

    if connection.vendor == "postgresql":
        component_query = (
            component_query.values("component_name")
            .order_by("component_name")
            .annotate(
                component_version=StringAgg(
                    "component_version", delimiter=separator, distinct=True, default=Value(""),
                ),
            )
        )
    else:
        component_query = component_query.values("component_name").order_by(
            "component_name",
        )
        component_query = component_query.annotate(
            component_version=Sql_GroupConcat(
                "component_version", separator=separator, distinct=True,
            ),
        )

    # Append counts
    component_query = component_query.annotate(total=Count("id")).order_by(
        "component_name",
    )
    component_query = component_query.annotate(
        active=Count("id", filter=Q(active=True)),
    )
    component_query = component_query.annotate(
        duplicate=(Count("id", filter=Q(duplicate=True))),
    )
    component_query = component_query.order_by(
        "-total",
    )  # Default sort by total descending

    filter_string_matching = get_system_setting("filter_string_matching", False)
    filter_class = ComponentFilterWithoutObjectLookups if filter_string_matching else ComponentFilter
    comp_filter = filter_class(request.GET, queryset=component_query)
    result = get_page_items(request, comp_filter.qs, 25)

    # Filter out None values for auto-complete
    component_words = component_query.exclude(
        component_name__isnull=True,
    ).values_list("component_name", flat=True)

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
