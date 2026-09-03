from dojo.product_attributes.api import lifecycle_path, origin_path, platform_path
from dojo.product_attributes.api.views import (
    ProductLifecycleViewSet,
    ProductOriginViewSet,
    ProductPlatformViewSet,
)


def add_product_attribute_urls(router):
    router.register(platform_path, ProductPlatformViewSet, basename="product_platform")
    router.register(lifecycle_path, ProductLifecycleViewSet, basename="product_lifecycle")
    router.register(origin_path, ProductOriginViewSet, basename="product_origin")
    return router
