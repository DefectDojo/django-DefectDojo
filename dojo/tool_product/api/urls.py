from dojo.tool_product.api.views import ToolProductSettingsViewSet


def add_tool_product_urls(router):
    router.register(r"tool_product_settings", ToolProductSettingsViewSet, basename="tool_product_settings")
    return router
