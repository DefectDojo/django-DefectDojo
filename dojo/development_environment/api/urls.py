from dojo.development_environment.api import path
from dojo.development_environment.api.views import DevelopmentEnvironmentViewSet


def add_development_environment_urls(router):
    router.register(path, DevelopmentEnvironmentViewSet, basename="development_environment")
    return router
