from dojo.product_type.api.views import ProductTypeViewSet


def add_product_type_urls(router):
    router.register("product_types", ProductTypeViewSet, basename="product_type")
    return router
