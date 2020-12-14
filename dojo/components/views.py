from django.shortcuts import render
from dojo.models import Finding
from django.db.models import Count, Q
from dojo.utils import add_breadcrumb, get_page_items
from dojo.filters import ComponentFilter
from dojo.components.group_concat import GroupConcat


def components(request):
    add_breadcrumb(title='Components', top_level=True, request=request)
    component_query = Finding.objects.filter().values("component_name")
    component_query = component_query.annotate(component_version=GroupConcat('component_version', distinct=True))
    component_query = component_query.annotate(total=Count('id')).order_by('component_name')
    component_query = component_query.annotate(active=Count('id', filter=Q(active=True)))
    component_query = component_query.annotate(duplicate=(Count('id', filter=Q(duplicate=True))))
    component_query = component_query.order_by('-total')  # Default sort by total descending

    comp_filter = ComponentFilter(request.GET, queryset=component_query)
    result = get_page_items(request, comp_filter.qs, 25)

    component_words = component_query.exclude(component_name__isnull=True).values_list('component_name', flat=True)

    return render(request, 'dojo/components.html', {
        'filter': comp_filter,
        'result': result,
        'component_words': sorted(set(component_words))
    })
