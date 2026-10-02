from dojo.engagement.api.views import EngagementPresetsViewset, EngagementViewSet


def add_engagement_urls(router):
    router.register("engagements", EngagementViewSet, basename="engagement")
    router.register("engagement_presets", EngagementPresetsViewset, basename="engagement_presets")
    return router
