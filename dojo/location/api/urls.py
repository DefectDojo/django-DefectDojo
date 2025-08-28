from dojo.location.api import finding_path, path, product_path
from dojo.location.api.views import LocationFindingReferenceViewSet, LocationProductReferenceViewSet, LocationViewSet
from dojo.location.types.url.api.urls import add_url_urls


def add_locations_urls(router):
    router.register(path, LocationViewSet, path)
    router.register(finding_path, LocationFindingReferenceViewSet, finding_path)
    router.register(product_path, LocationProductReferenceViewSet, product_path)
    add_url_urls(router)
    return router
