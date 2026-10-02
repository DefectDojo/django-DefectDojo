from dojo.risk_acceptance.api import path
from dojo.risk_acceptance.api.views import RiskAcceptanceViewSet


def add_risk_acceptance_urls(router):
    router.register(path, RiskAcceptanceViewSet, basename="risk_acceptance")
    return router
