from dojo.finding.api.views import FindingTemplatesViewSet, FindingViewSet


def add_finding_urls(router):
    router.register("finding_templates", FindingTemplatesViewSet, basename="finding_template")
    router.register("findings", FindingViewSet, basename="finding")
    return router
