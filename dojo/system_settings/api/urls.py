from dojo.system_settings.api import path
from dojo.system_settings.api.views import SystemSettingsViewSet


def add_system_settings_urls(router):
    router.register(path, SystemSettingsViewSet, basename="system_settings")
    return router
