# Dojo
from dojo.authorization.authorization_decorators import user_is_configuration_authorized
from dojo.authorization.roles_permissions import Permissions
from dojo.models import Dojo_User
from dojo.utils import get_page_items, add_breadcrumb
from dojo.notifications.helper import create_notification, send_mail_notification
from dojo.engine_tools.models import FindingExclusion
from dojo.engine_tools.filters import FindingExclusionFilter
from dojo.engine_tools.forms import CreateFindingExclusionForm, FindingExclusionDiscussionForm

# Utils
from datetime import datetime, timedelta
from django.contrib import messages
from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.http.response import HttpResponseRedirect
from django.urls import reverse
from django.utils import timezone
from django.shortcuts import render, redirect, get_object_or_404


@user_is_configuration_authorized("dojo.view_findingexclusion")
def finding_exclusions(request: HttpRequest):
    finding_exclusions = FindingExclusion.objects.all()
    finding_exclusions = FindingExclusionFilter(request.GET,
                                                queryset=finding_exclusions)
    paged_finding_exclusion = get_page_items(request,
                                             finding_exclusions.qs,
                                             25)

    add_breadcrumb(title="FindingExclusion", top_level=True, request=request)
    return render(request, "dojo/view_finding_exclusion.html", {
        "exclusions": paged_finding_exclusion,
        "filtered": finding_exclusions,
        "name": "Finding Exclusions",
    })


@user_is_configuration_authorized("dojo.add_findingexclusion")
def create_finding_exclusion(request):
    default_unique_id = request.GET.get('unique_id', '')
    
    form = CreateFindingExclusionForm(initial={'unique_id_from_tool': default_unique_id})
    finding_exclusion = None

    if request.method == "POST":
        form = CreateFindingExclusionForm(request.POST)
        if form.is_valid():
            exclusion = form.save(commit=False)
            exclusion.created_by = request.user
            exclusion.expiration_date = timezone.now() + timedelta(days=30)
            exclusion.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                "Exclusion successfully created.",
                extra_tags="alert-success")
            return HttpResponseRedirect(reverse("finding_exclusions"))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                "Please correct any errors displayed below.",
                extra_tags="alert-danger")

    add_breadcrumb(title="Create Exclusion",
                   top_level=False,
                   request=request)

    return render(request, "dojo/create_finding_exclusion.html", {
        "finding_exclusion": finding_exclusion,
        "form": form,
        "name": "Create finding exclusion",
    })


@user_is_configuration_authorized("dojo.view_findingexclusion")
def show_finding_exclusion(request: HttpRequest, fxid: str) -> HttpResponse:
    """Show a find exclusion and the proccess status

    Args:
        request (HttpRequest): Http request object
        fxid (str): Finding exclusion ID

    Returns:
        HttpResponse: HttpResponse object via django template
    """
    
    finding_exclusion = get_object_or_404(FindingExclusion, pk=fxid)
    discussion_form = FindingExclusionDiscussionForm()
    
    add_breadcrumb(title=finding_exclusion.unique_id_from_tool,
                   top_level=True,
                   request=request)

    return render(request, "dojo/show_finding_exclusion.html", {
        "finding_exclusion": finding_exclusion,
        "name": f"Finding exclusion | {finding_exclusion.unique_id_from_tool}",
        'discussion_form': discussion_form,
    })
    
    
def add_finding_exclusion_discussion(request: HttpRequest, fxid: str) -> HttpResponse:
    """Add a discussion for an finding exclusion

    Args:
        request (HttpRequest): Http request object
        fxid (str): Finding exclusion ID

    Returns:
        HttpResponse: Http response object via Django template
    """
    finding_exclusion = get_object_or_404(FindingExclusion, uuid=fxid)
    
    
    if request.method == 'POST':
        form = FindingExclusionDiscussionForm(request.POST)
        if form.is_valid():
            discussion = form.save(commit=False)
            discussion.finding_exclusion = finding_exclusion
            discussion.author = request.user
            discussion.save()
            return redirect('finding_exclusion', fxid=fxid)
    
    return redirect('finding_exclusion', fxid=fxid)


@user_is_configuration_authorized("dojo.review_findingexclusion")
def review_finding_exclusion_request(
    request: HttpRequest, fxid: str, **kwargs: dict[str, any]
    ) -> HttpResponse:
    """Change the status of the finding exclusion to reviewed.

    Args:
        request (HttpRequest): Http request object
        fxid (str): Finding exclusion ID
        
    Returns:
        HttpResponse: Http response object via Django template
    """
    if request.method == 'POST':
        finding_exclusion = get_object_or_404(FindingExclusion, uuid=fxid)
        finding_exclusion.status = "Reviewed"
        finding_exclusion.reviewed_at = datetime.now()
        finding_exclusion.status_updated_at = datetime.now()
        finding_exclusion.status_updated_by = request.user
        finding_exclusion.save()
        
        create_notification(event="other",
                            title=f"Review applied to the whitelisting request - {finding_exclusion.unique_id_from_tool}",
                            description=f"Review applied to the whitelisting request - {finding_exclusion.unique_id_from_tool}, You will be notified of the final result.",
                            url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
                            recipients=[finding_exclusion.created_by])
        
        prisma_cyber_user =  Dojo_User(email=settings.PRISMA_CYBER_EMAIL)

        kwargs["description"] = finding_exclusion.reason
        kwargs["title"] = f"Evaluación Elegibilidad Vulnerabilidad Lista Blanca {finding_exclusion.unique_id_from_tool}"
        kwargs["subject"] = f"Evaluación Elegibilidad Vulnerabilidad Lista Blanca {finding_exclusion.unique_id_from_tool}"
        kwargs["url"] = reverse("finding_exclusion", args=[str(finding_exclusion.pk)])
        
        send_mail_notification("other", prisma_cyber_user, **kwargs)
        
        messages.add_message(
                request,
                messages.SUCCESS,
                "Finding Exclusion reviewed.",
                extra_tags="alert-success")
            
        return redirect('finding_exclusion', fxid=fxid)
    
    return redirect('finding_exclusion', fxid=fxid)


def accept_find_exclusion(request: HttpRequest, fxid: str) -> HttpResponse:
    pass