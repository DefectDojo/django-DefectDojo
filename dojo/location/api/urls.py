from dojo.location.api import finding_path, path, product_path
from dojo.location.api.views import LocationFindingReferenceViewSet, LocationProductReferenceViewSet, LocationViewSet


def add_locations_urls(router):
    router.register(path, LocationViewSet, path)
    router.register(finding_path, LocationFindingReferenceViewSet, finding_path)
    router.register(product_path, LocationProductReferenceViewSet, product_path)
    return router
