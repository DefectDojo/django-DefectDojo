from dojo.product.api.views import ProductAPIScanConfigurationViewSet, ProductViewSet


def add_product_urls(router):
    router.register("products", ProductViewSet, basename="product")
    router.register("product_api_scan_configurations", ProductAPIScanConfigurationViewSet, basename="product_api_scan_configuration")
    return router
