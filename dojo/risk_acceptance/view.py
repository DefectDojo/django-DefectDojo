from dojo.models import Risk_Acceptance
from django.shortcuts import get_object_or_404 
from django.urls import reverse
from dojo.risk_acceptance.helper import update_or_create_url_risk_acceptance
from dojo.utils import redirect_to_return_url_or_else


def generate_risk_acceptance_url(request, eid, raid):
    risk_pending =  get_object_or_404(Risk_Acceptance, pk=raid)
    update_or_create_url_risk_acceptance(risk_pending)
    return redirect_to_return_url_or_else(request, reverse("view_risk_acceptance", args=(eid, raid)))

