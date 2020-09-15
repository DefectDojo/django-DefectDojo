from django.shortcuts import render
from dojo.models import Finding
from django.db.models import Count, Q
from dojo.utils import add_breadcrumb, get_page_items
from dojo.filters import OpenFindingFilter

def components(request):
    add_breadcrumb(title='Components', top_level=True, request=request)
    component_query = Finding.objects.filter().values("component_name", "component_version")
    component_query = component_query.annotate(total=Count('id')).order_by('component_name','component_version')
    component_query = component_query.annotate(active=Count('id',filter=Q(active=True)))
    component_query = component_query.annotate(duplicate=(Count('id', filter=Q(duplicate=True))))

    result = get_page_items(request, component_query , 25)

    return render(request, 'dojo/components.html', {
        'result': result
    })    