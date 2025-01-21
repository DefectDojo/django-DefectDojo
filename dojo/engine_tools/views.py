# Dojo
from dojo.templatetags.authorization_tags import is_in_group
from dojo.utils import get_page_items, add_breadcrumb
from dojo.notifications.helper import create_notification
from dojo.engine_tools.models import FindingExclusion
from dojo.engine_tools.filters import FindingExclusionFilter
from dojo.engine_tools.forms import CreateFindingExclusionForm, FindingExclusionDiscussionForm, EditFindingExclusionForm
from dojo.engine_tools.helpers import (
    add_findings_to_whitelist, 
    get_approvers_members, 
    get_reviewers_members, 
    Constants, 
    expire_finding_exclusion_immediately,
    send_mail_to_cybersecurity,
    check_priorization
)

# Utils
from datetime import datetime, timedelta
from django.contrib import messages
from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.http.response import HttpResponseRedirect
from django.core.exceptions import PermissionDenied
from django.urls import reverse
from django.utils import timezone
from django.shortcuts import render, redirect, get_object_or_404
from django.db import transaction


def finding_exclusions(request: HttpRequest):
    finding_exclusions = FindingExclusion.objects.all().order_by("-create_date")
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


def create_finding_exclusion(request: HttpRequest) -> HttpResponse:
    default_unique_id = request.GET.get('unique_id', '')
    default_practice = request.GET.get('practice', '') or request.POST.get('practice', '')
    
    duplicate_finding_exclusions = FindingExclusion.objects.filter(
            unique_id_from_tool__in=[default_unique_id],
    ).exclude(status="Expired").first()
    
    if duplicate_finding_exclusions:
        if duplicate_finding_exclusions.status == "Accepted":
            messages.add_message(
                request,
                messages.INFO,
                f"There is already a request in status '{duplicate_finding_exclusions.status}' for this CVE, This will be whitelisted.",
                extra_tags="alert-success")
            relative_url = reverse("finding_exclusion", args=[str(duplicate_finding_exclusions.pk)])
            add_findings_to_whitelist.apply_async(args=(duplicate_finding_exclusions.unique_id_from_tool, relative_url,))
            
        else:
            messages.add_message(
                request,
                messages.INFO,
                f"There is already a request in status '{duplicate_finding_exclusions.status}' for this CVE, please consult the id '{duplicate_finding_exclusions.uuid}' in this section.",
                extra_tags="alert-info")
        
        return HttpResponseRedirect(reverse("finding_exclusions"))
    
    form = CreateFindingExclusionForm(initial={
            "unique_id_from_tool": default_unique_id,
            "practice": default_practice
        })

    finding_exclusion = None

    if request.method == "POST":
        form = CreateFindingExclusionForm(request.POST)
        list_type = request.POST.get(key="type")
        if list_type == "black_list":
            if not is_in_group(request.user, Constants.REVIEWERS_MAINTAINER_GROUP.value):
                raise PermissionDenied
        
        if form.is_valid():
            exclusion = form.save(commit=False)
            exclusion.practice = default_practice
            exclusion.created_by = request.user
            exclusion.save()
            
            cve = request.POST.get(key="unique_id_from_tool")
            
            reviewers = get_reviewers_members()
            
            create_notification(
                event="finding_exclusion_request",
                title=f"A new request has been created to add {cve} to the {list_type}.",
                description=f"A new request has been created to add {cve} to the {list_type}.",
                url=reverse("finding_exclusion", args=[str(exclusion.pk)]),
                recipients=reviewers
            )
            
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
                   top_level=False,
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


def review_finding_exclusion_request(
    request: HttpRequest, fxid: str
    ) -> HttpResponse:
    """Change the status of the finding exclusion to reviewed.

    Args:
        request (HttpRequest): Http request object
        fxid (str): Finding exclusion ID
        
    Returns:
        HttpResponse: Http response object via Django template
    """
    if not is_in_group(request.user, Constants.REVIEWERS_MAINTAINER_GROUP.value):
        raise PermissionDenied
    
    finding_exclusion = get_object_or_404(FindingExclusion, uuid=fxid)
    
    finding_exclusion.status = "Reviewed"
    finding_exclusion.reviewed_at = datetime.now()
    finding_exclusion.status_updated_at = datetime.now()
    finding_exclusion.status_updated_by = request.user
    finding_exclusion.save()
    
    create_notification(event="finding_exclusion_request",
                        title=f"Review applied to the whitelisting request - {finding_exclusion.unique_id_from_tool}",
                        description=f"Review applied to the whitelisting request - {finding_exclusion.unique_id_from_tool}, You will be notified of the final result.",
                        url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
                        recipients=[finding_exclusion.created_by.username])
    
    approvers = get_approvers_members()
    
    create_notification(event="finding_exclusion_request",
                        title=f"Eligibility Assessment Vulnerability Whitelist - {finding_exclusion.unique_id_from_tool}",
                        description=f"Eligibility Assessment Vulnerability Whitelist - {finding_exclusion.unique_id_from_tool}.",
                        url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
                        recipients=approvers)
    
    send_mail_to_cybersecurity(finding_exclusion)
    
    messages.add_message(
            request,
            messages.SUCCESS,
            "Finding Exclusion reviewed.",
            extra_tags="alert-success")
        
    return redirect('finding_exclusion', fxid=fxid)
    



def accept_finding_exclusion_request(request: HttpRequest, fxid: str) -> HttpResponse:
    if not is_in_group(request.user, Constants.APPROVERS_CYBERSECURITY_GROUP.value):
        raise PermissionDenied
    try:
        with transaction.atomic():
            finding_exclusion = get_object_or_404(FindingExclusion, uuid=fxid)
                
            finding_exclusion.status = "Accepted"
            finding_exclusion.final_status = "Accepted"
            finding_exclusion.accepted_at = datetime.now()
            finding_exclusion.status_updated_at = datetime.now()
            finding_exclusion.status_updated_by = request.user
            finding_exclusion.expiration_date = timezone.now() + timedelta(days=int(settings.FINDING_EXCLUSION_EXPIRATION_DAYS))
            finding_exclusion.save()
            
            relative_url = reverse("finding_exclusion", args=[str(finding_exclusion.pk)])
            add_findings_to_whitelist.apply_async(args=(finding_exclusion.unique_id_from_tool, str(relative_url),))
                    
    except Exception as e:
        messages.add_message(
                request,
                messages.ERROR,
                f"An error occurred while accepting this finding exclusion, please try again later. Details: {e.with_traceback()}",
                extra_tags="alert-success")
        return redirect('finding_exclusion', fxid=fxid)
    
    maintainers = get_reviewers_members()
    
    create_notification(event="finding_exclusion_approved",
                        title=f"Whitelisting request accepted - {finding_exclusion.unique_id_from_tool}",
                        description=f"Whitelisting request accepted - {finding_exclusion.unique_id_from_tool}",
                        url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
                        recipients=[finding_exclusion.created_by.username] + maintainers)
    
    messages.add_message(
            request,
            messages.SUCCESS,
            "Finding Exclusion accepted.",
            extra_tags="alert-success")
        
    return redirect('finding_exclusion', fxid=fxid)
    



def reject_finding_exclusion_request(request: HttpRequest, fxid: str) -> HttpResponse:
    if not is_in_group(request.user, Constants.REVIEWERS_MAINTAINER_GROUP.value) and \
        not is_in_group(request.user, Constants.APPROVERS_CYBERSECURITY_GROUP.value):
        raise PermissionDenied
    finding_exclusion = get_object_or_404(FindingExclusion, uuid=fxid)
    
    finding_exclusion.status = "Rejected"
    finding_exclusion.final_status = "Rejected"
    finding_exclusion.status_updated_at = datetime.now()
    finding_exclusion.status_updated_by = request.user
    finding_exclusion.save()
    
    create_notification(
        event="finding_exclusion_rejected",
        title=f"Whitelisting request rejected - {finding_exclusion.unique_id_from_tool}",
        description=f"Whitelisting request rejected - {finding_exclusion.unique_id_from_tool}.",
        url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
        recipients=[finding_exclusion.created_by.username]
    )
    
    messages.add_message(
            request,
            messages.SUCCESS,
            "Finding Exclusion rejected.",
            extra_tags="alert-success")
        
    return redirect('finding_exclusion', fxid=fxid)
    
            
def expire_finding_exclusion_request(request: HttpRequest, fxid: str) -> HttpResponse:
    if not is_in_group(request.user, Constants.REVIEWERS_MAINTAINER_GROUP.value) and \
        not is_in_group(request.user, Constants.APPROVERS_CYBERSECURITY_GROUP.value):
        raise PermissionDenied
    finding_exclusion = get_object_or_404(FindingExclusion, uuid=fxid)
    
    expire_finding_exclusion_immediately.apply_async(args=(str(finding_exclusion.uuid),))
    
    messages.add_message(
            request,
            messages.SUCCESS,
            f"Finding Exclusion {finding_exclusion.uuid} expired.",
            extra_tags="alert-success")
    
    return redirect('finding_exclusion', fxid=fxid)
    

def edit_finding_exclusion(request: HttpRequest, fxid: str) -> HttpResponse:
    if not is_in_group(request.user, Constants.REVIEWERS_MAINTAINER_GROUP.value):
        raise PermissionDenied

    finding_exclusion = get_object_or_404(FindingExclusion, uuid=fxid)

    if request.method == 'POST':
        form = EditFindingExclusionForm(request.POST, instance=finding_exclusion)
        if form.is_valid():
            form.save()
            
            return redirect('finding_exclusion', fxid=fxid)
    else:
        form = EditFindingExclusionForm(instance=finding_exclusion)

    return render(request, 'dojo/edit_finding_exclusion.html', {'form': form})


def edit_finding_exclusion_request(request: HttpRequest, fxid: str) -> HttpResponse:
    if not is_in_group(request.user, Constants.REVIEWERS_MAINTAINER_GROUP.value):
        raise PermissionDenied
    
    return redirect('edit_finding_exclusion', fxid=fxid)
        
        
def execute_priorization_check(request: HttpRequest) -> HttpResponse:
    """Execute the priorization check task inmediately"""
    if not is_in_group(request.user, Constants.REVIEWERS_MAINTAINER_GROUP.value):
        raise PermissionDenied
    
    check_priorization.apply_async()
    
    messages.add_message(
        request,
        messages.SUCCESS,
        "Priorization of findings updated",
        extra_tags="alert-success")
    
    return HttpResponseRedirect(reverse("finding_exclusions"))