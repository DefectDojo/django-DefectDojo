from django.urls import re_path, path
from dojo.risk_acceptance import view


urlpatterns = [
    re_path(r"^engagement/(?P<eid>\d+)/risk_acceptance/(?P<raid>\d+)/refresh_url$", view.generate_risk_acceptance_url, name="refresh_url"),
]
