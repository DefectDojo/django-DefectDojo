# Dojo
from dojo.authorization.authorization_decorators import (
    user_is_configuration_authorized, user_is_authorized, user_has_global_permission_or_403
)
from dojo.authorization.authorization import user_has_permission_or_403
from dojo.authorization.roles_permissions import Permissions
from dojo.models import Dojo_User, Finding, Product
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
    product_id = request.GET.get('product_id', '')
    
    if product_id:
        product = get_object_or_404(Product, pk=product_id)
        user_has_permission_or_403(request.user, product, Permissions.Finding_Exclusion_Add)
    else:
        product = None
        user_has_global_permission_or_403(
            request.user, Permissions.Finding_Exclusion_Add,
        )
    
    duplicate_finding_exclusions = FindingExclusion.objects.filter(
            unique_id_from_tool__in=[default_unique_id],
    ).first()
    
    if duplicate_finding_exclusions:
        messages.add_message(
            request,
            messages.ERROR,
            f"There is already a request in status '{duplicate_finding_exclusions.status}' for this CVE, please consult the id '{duplicate_finding_exclusions.uuid}' in this section.",
            extra_tags="alert-danger")
        
        return HttpResponseRedirect(reverse("finding_exclusions"))
    
    if default_unique_id:
        form = CreateFindingExclusionForm(initial={'unique_id_from_tool': default_unique_id},
                                        disable_unique_id=True)
    else:
        form = CreateFindingExclusionForm()
    finding_exclusion = None

    if request.method == "POST":
        form = CreateFindingExclusionForm(request.POST)
        list_type = request.POST.get(key="type")
        if list_type == "black_list":
            user_has_global_permission_or_403(
                request.user, Permissions.Finding_Exclusion_Review,
        )
        
        if form.is_valid():
            exclusion = form.save(commit=False)
            exclusion.created_by = request.user
            exclusion.product = product
            exclusion.expiration_date = timezone.now() + timedelta(days=30)
            exclusion.save()
            
            cve = request.POST.get(key="unique_id_from_tool")
            
            create_notification(
                event="other",
                title=f"A new request has been created to add {cve} to the {list_type}.",
                description=f"A new request has been created to add {cve} to the {list_type}.",
                url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
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
    
    if finding_exclusion.product is not None: 
        user_has_permission_or_403(
            request.user, finding_exclusion, Permissions.Finding_Exclusion_View
        )
    else:
        user_has_global_permission_or_403(
            request.user, Permissions.Finding_Exclusion_View,
        )
    
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
        
        if finding_exclusion.product is not None: 
            user_has_permission_or_403(
                request.user, finding_exclusion, Permissions.Finding_Exclusion_Review
            )
        else:
            user_has_global_permission_or_403(
                request.user, Permissions.Finding_Exclusion_Review,
            )
        
        finding_exclusion.status = "Reviewed"
        finding_exclusion.reviewed_at = datetime.now()
        finding_exclusion.status_updated_at = datetime.now()
        finding_exclusion.status_updated_by = request.user
        finding_exclusion.save()
        
        create_notification(event="other",
                            title=f"Review applied to the whitelisting request - {finding_exclusion.unique_id_from_tool}",
                            description=f"Review applied to the whitelisting request - {finding_exclusion.unique_id_from_tool}, You will be notified of the final result.",
                            url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
                            product=finding_exclusion.product,
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


def accept_finding_exclusion_request(request: HttpRequest, fxid: str) -> HttpResponse:
    if request.method == 'POST':
        try:
            with transaction.atomic():
                finding_exclusion = get_object_or_404(FindingExclusion, uuid=fxid)
                
                if finding_exclusion.product is not None: 
                    user_has_permission_or_403(
                        request.user, finding_exclusion, Permissions.Finding_Exclusion_Accept
                    )
                else:
                    user_has_global_permission_or_403(
                        request.user, Permissions.Finding_Exclusion_Accept,
                    )
                    
                finding_exclusion.status = "Accepted"
                finding_exclusion.final_status = "Accepted"
                finding_exclusion.accepted_at = datetime.now()
                finding_exclusion.status_updated_at = datetime.now()
                finding_exclusion.status_updated_by = request.user
                finding_exclusion.save()
                
                findings = Finding.objects.filter(cve=finding_exclusion.unique_id_from_tool)
                
                for finding in findings:
                    if not 'white_list' in finding.tags:
                        finding.tags.add("white_list")
                    finding.active = False
                    finding.save()       
                
        except Exception as e:
            messages.add_message(
                    request,
                    messages.ERROR,
                    f"An error occurred while accepting this finding exclusion, please try again later. Details: {e.with_traceback()}",
                    extra_tags="alert-success")
            return redirect('finding_exclusion', fxid=fxid)
        
        create_notification(event="other",
                            title=f"Whitelisting request accepted - {finding_exclusion.unique_id_from_tool}",
                            description=f"Whitelisting request accepted - {finding_exclusion.unique_id_from_tool}, You will be notified of the final result.",
                            url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
                            product=finding_exclusion.product,
                            recipients=[finding_exclusion.created_by])
        
        messages.add_message(
                request,
                messages.SUCCESS,
                "Finding Exclusion accepted.",
                extra_tags="alert-success")
            
        return redirect('finding_exclusion', fxid=fxid)
    
    return redirect('finding_exclusion', fxid=fxid)


def reject_finding_exclusion_request(request: HttpRequest, fxid: str) -> HttpResponse:
    if request.method == 'POST':
        finding_exclusion = get_object_or_404(FindingExclusion, uuid=fxid)
        
        if finding_exclusion.product is not None: 
            user_has_permission_or_403(
                request.user, finding_exclusion, Permissions.Finding_Exclusion_Reject
            )
        else:
            user_has_global_permission_or_403(
                request.user, Permissions.Finding_Exclusion_Reject,
            )
        
        finding_exclusion.status = "Rejected"
        finding_exclusion.final_status = "Rejected"
        finding_exclusion.status_updated_at = datetime.now()
        finding_exclusion.status_updated_by = request.user
        finding_exclusion.save()
        
        create_notification(
            event="other",
            title=f"Whitelisting request rejected - {finding_exclusion.unique_id_from_tool}",
            description=f"Whitelisting request rejected - {finding_exclusion.unique_id_from_tool}, You will be notified of the final result.",
            url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
            product=finding_exclusion.product,
            recipients=[finding_exclusion.created_by]
        )
        
        messages.add_message(
                request,
                messages.SUCCESS,
                "Finding Exclusion rejected.",
                extra_tags="alert-success")
            
        return redirect('finding_exclusion', fxid=fxid)
    
    return redirect('finding_exclusion', fxid=fxid)