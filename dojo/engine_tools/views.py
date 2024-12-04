from dojo.utils import get_page_items, add_breadcrumb
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.http.response import HttpResponseRedirect
from django.urls import reverse
from dojo.notifications.helper import create_notification
from dojo.engine_tools.models import FindingExclusion, FindingExclusionDiscussion
from dojo.engine_tools.filters import FindingExclusionFilter
from dojo.engine_tools.forms import CreateFindingExclusionForm, FindingExclusionDiscussionForm


# @user_is_configuration_authorized("dojo.view_engagement_survey")
def finding_exclusions(request):
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


def create_finding_exclusion(request):
    default_unique_id = request.GET.get('unique_id', '')
    
    form = CreateFindingExclusionForm(initial={'unique_id_from_tool': default_unique_id})
    finding_exclusion = None

    if request.method == "POST":
        form = CreateFindingExclusionForm(request.POST)
        if form.is_valid():
            exclusion = form.save(commit=False)
            exclusion.created_by = request.user
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


def review_finding_exclusion_request(request: HttpRequest, fxid: str):
    """_summary_

    Args:
        request (HttpRequest): _description_
        fxid (str): _description_
    """
    if request.method == 'POST':
        finding_exclusion = get_object_or_404(FindingExclusion, uuid=fxid)
        finding_exclusion.status = "Reviewed"
        finding_exclusion.save()
        
        create_notification(event="stale_engagement",
                            title="",
                            description="",
                            url=reverse("finding_exclusion", fxid=finding_exclusion.pk),
                            recipients=[finding_exclusion.created_by])