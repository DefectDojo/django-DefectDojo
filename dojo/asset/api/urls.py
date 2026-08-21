from dojo.asset.api.views import (
    AssetAPIScanConfigurationViewSet,
    AssetViewSet,
)


def add_asset_urls(router):
    router.register(r"assets", AssetViewSet, basename="asset")
    router.register(r"asset_api_scan_configurations", AssetAPIScanConfigurationViewSet,
                    basename="asset_api_scan_configuration")
    # RBAC alias endpoints moved to Pro under legacy authorization:
    #   asset_groups, asset_members → pro/product_groups, pro/product_members
    return router
