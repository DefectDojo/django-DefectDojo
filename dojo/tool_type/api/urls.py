from dojo.tool_type.api.views import ToolTypesViewSet


def add_tool_type_urls(router):
    router.register(r"tool_types", ToolTypesViewSet, basename="tool_type")
    return router
