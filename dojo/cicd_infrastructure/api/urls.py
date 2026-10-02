from dojo.cicd_infrastructure.api.views import CICDInfrastructureViewSet


def add_cicd_infrastructure_urls(router):
    router.register(r"cicd_infrastructure", CICDInfrastructureViewSet, basename="cicd_infrastructure")
    return router
