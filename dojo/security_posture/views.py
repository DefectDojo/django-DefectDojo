from django.http import HttpRequest, HttpResponse
from dojo.decorators import dojo_ratelimit_view
from django.middleware.csrf import get_token
from dojo.utils import (
    add_breadcrumb)
from django.shortcuts import render
from django.conf import settings
from dojo.authorization.authorization_decorators import user_is_authorized


@dojo_ratelimit_view()
def security_posture_view(request: HttpRequest) -> HttpResponse:
    page_name = ('security_posture')
    engagement_id = request.GET.get('engagement_id')
    engagement_name = request.GET.get('engagement_name')
    user = request.user.id
    cookie_csrftoken = get_token(request)
    cookie_sessionid = request.COOKIES.get('sessionid', '')
    base_params = f"?csrftoken={cookie_csrftoken}&sessionid={cookie_sessionid}"
    base_params += f"&engagement_id={engagement_id}" if engagement_id else ""
    base_params += f"&engagement_name={engagement_name}" if engagement_name else ""
    add_breadcrumb(title=page_name, top_level=not len(request.GET), request=request)
    return render(request, 'dojo/generic_view.html', {
        'actions': page_name,
        'url': f"{settings.MF_FRONTEND_DEFECT_DOJO_URL}/secure/product/safety-position{base_params}",  
        'user': user})
