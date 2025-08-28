from dojo.location.types.url.api import path
from dojo.location.types.url.api.views import URLViewSet


def add_url_urls(router):
    router.register(path, URLViewSet, path)
    return router
