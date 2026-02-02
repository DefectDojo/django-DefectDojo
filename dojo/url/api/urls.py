from dojo.url.api import path
from dojo.url.api.views import URLViewSet


def add_url_urls(router):
    router.register(path, URLViewSet, path)
    return router
