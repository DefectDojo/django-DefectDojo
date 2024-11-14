from dojo.models import Risk_Acceptance
from django.shortcuts import get_object_or_404, render

def refresh_risk_acceptance_url(request, raid):
    # obtiene el risk acceptance object
    ra =  get_object_or_404(Risk_Acceptance, pk=raid)
    # actulizar actulizar expiration id
    

    # genear url 
    # enviar correo electronico 
    # no hace nada.