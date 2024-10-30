from django.db.models import Count, Q
from django.shortcuts import render
from dojo.models import Component
from dojo.authorization.roles_permissions import Permissions
from dojo.filters import ComponentFilter, ComponentFilterWithoutObjectLookups
from dojo.engagement.queries import get_authorized_engagements
from dojo.utils import add_breadcrumb, get_page_items, get_system_setting


def components(request):
    add_breadcrumb(title="Components", top_level=True, request=request)
    
    # Obtener los engagements a los que el usuario tiene acceso
    authorized_engagements = get_authorized_engagements(Permissions.Engagement_View)

    # Filtrar componentes basados en los engagements autorizados
    component_query = Component.objects.filter(engagement__in=authorized_engagements)

    # Agregar anotaciones para contar findings asociados a cada componente
    component_query = component_query.annotate(
        total_findings=Count('finding__id', distinct=True),  # Contar todos los findings asociados
        active_findings=Count('finding__id', filter=Q(finding__active=True), distinct=True),  # Contar findings activos
        duplicate_findings=Count('finding__id', filter=Q(finding__duplicate=True), distinct=True)  # Contar findings duplicados
    )

    # Ordenar por el número total de findings
    component_query = component_query.order_by("-total_findings")

    # Aplicar filtros según la configuración del sistema
    filter_string_matching = get_system_setting("filter_string_matching", False)
    filter_class = ComponentFilterWithoutObjectLookups if filter_string_matching else ComponentFilter
    comp_filter = filter_class(request.GET, queryset=component_query)

    # Paginación
    result = get_page_items(request, comp_filter.qs, 25)

    # Autocompletado para los nombres de los componentes
    component_words = component_query.exclude(name__isnull=True).values_list("name", flat=True)

    # Renderizar la vista con la plantilla
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