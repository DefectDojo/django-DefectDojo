from dojo.models import Risk_Acceptance
from django.shortcuts import get_object_or_404, render
from dojo.decorators import dojo_ratelimit_view
from django.conf import settings
from dojo.utils import add_breadcrumb
from django.shortcuts import get_object_or_404 
from django.urls import reverse
from django.http import HttpResponse, HttpRequest
from django.middleware.csrf import get_token
from dojo.risk_acceptance.helper import update_or_create_url_risk_acceptance
from dojo.utils import redirect_to_return_url_or_else


def generate_risk_acceptance_url(request, eid, raid):
    risk_pending =  get_object_or_404(Risk_Acceptance, pk=raid)
    update_or_create_url_risk_acceptance(risk_pending, send_notification=True)
    return redirect_to_return_url_or_else(request, reverse("view_risk_acceptance", args=(eid, raid)))

@dojo_ratelimit_view()
def view_all_risk_acceptance(request: HttpRequest) -> HttpResponse:
    page_name = ('view_all_risk_acceptance')
    user = request.user.id
    cookie_csrftoken = get_token(request)
    cookie_sessionid = request.COOKIES.get('sessionid', '')
    base_params = f"?csrftoken={cookie_csrftoken}&sessionid={cookie_sessionid}"
    add_breadcrumb(title=page_name, request=request, top_level=True)
    return render(request, 'dojo/generic_view.html', {
        'actions': page_name,
        'url': f"{settings.MF_FRONTEND_DEFECT_DOJO_URL}/acceptance/list{base_params}",
        'user': user})

@dojo_ratelimit_view()
def view_risk_acceptance(request: HttpRequest, eid) -> HttpResponse:
    page_name = ('view_risk_acceptance')
    user = request.user.id
    cookie_csrftoken = get_token(request)
    cookie_sessionid = request.COOKIES.get('sessionid', '')
    base_params = f"?csrftoken={cookie_csrftoken}&sessionid={cookie_sessionid}"
    base_params = f"{base_params}&engagement={eid}"
    add_breadcrumb(title=page_name, request=request, top_level=True)
    return render(request, 'dojo/generic_view.html', {
        'actions': page_name,
        'url': f"{settings.MF_FRONTEND_DEFECT_DOJO_URL}/acceptance/{base_params}",
        'user': user})

