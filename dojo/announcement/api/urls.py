from dojo.announcement.api import path
from dojo.announcement.api.views import AnnouncementViewSet


def add_announcement_urls(router):
    router.register(path, AnnouncementViewSet, basename="announcement")
    return router
