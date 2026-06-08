from dojo.finding.api.views import (
    BurpRawRequestResponseViewSet,
    FindingTemplatesViewSet,
    FindingViewSet,
)


def add_finding_urls(router):
    router.register("finding_templates", FindingTemplatesViewSet, basename="finding_template")
    router.register("findings", FindingViewSet, basename="finding")
    router.register("request_response_pairs", BurpRawRequestResponseViewSet, basename="request_response_pairs")
    return router
