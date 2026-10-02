from dojo.tool_config.api.views import ToolConfigurationsViewSet


def add_tool_config_urls(router):
    router.register(r"tool_configurations", ToolConfigurationsViewSet, basename="tool_configuration")
    return router
