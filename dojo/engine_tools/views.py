# Dojo
from dojo.templatetags.authorization_tags import is_in_group, has_permission_to_reclassify_orphans, is_in_reviewer_group
from dojo.utils import get_page_items, add_breadcrumb
from dojo.notifications.helper import create_notification
from dojo.engine_tools.models import FindingExclusion, FindingExclusionDiscussion, FindingExclusionLog
from dojo.engine_tools.filters import FindingExclusionFilter
from dojo.engine_tools.forms import CreateFindingExclusionForm, FindingExclusionDiscussionForm, EditFindingExclusionForm
from dojo.models import Product, Product_Type, System_Settings
from dojo.engine_tools.helpers import (
    add_findings_to_whitelist, 
    get_reviewers_members, 
    Constants, 
    expire_finding_exclusion_immediately,
    send_mail_to_cybersecurity,
    has_valid_comments,
    add_findings_to_blacklist,
    remove_findings_from_deleted_finding_exclusions
)

# Utils
from datetime import datetime, timedelta
from django.contrib import messages
from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.http.response import HttpResponseRedirect, JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.core.exceptions import PermissionDenied
from django.urls import reverse
from django.utils import timezone
from django.shortcuts import render, redirect, get_object_or_404
from django.db import transaction
from django.db.models import Q
import json
import pandas as pd
from openpyxl.styles import Font, PatternFill


def finding_exclusions(request: HttpRequest):
    finding_exclusions = FindingExclusion.objects.all().order_by("-create_date")
    finding_exclusions = FindingExclusionFilter(request.GET,
                                                queryset=finding_exclusions)
    paged_finding_exclusion = get_page_items(request,
                                             finding_exclusions.qs,
                                             10)

    add_breadcrumb(title="Vulnerability Black & White Lists", top_level=True, request=request)
    return render(request, "dojo/view_finding_exclusion.html", {
        "exclusions": paged_finding_exclusion,
        "filtered": finding_exclusions,
        "name": "Vulnerability Black & White Lists",
    })


def create_finding_exclusion(request: HttpRequest) -> HttpResponse:
    default_unique_id = request.GET.get('unique_id', '')
    default_practice = request.GET.get('practice', '') or request.POST.get('practice', '')
    
    duplicate_finding_exclusions = FindingExclusion.objects.filter(
            unique_id_from_tool__in=[default_unique_id],
            engagements__isnull=True,
            product__isnull=True
    ).exclude(status__in=["Rejected"]).first()
    
    if duplicate_finding_exclusions:
        if duplicate_finding_exclusions.status == "Accepted":
            messages.add_message(
                request,
                messages.INFO,
                f"There is already a request in status '{duplicate_finding_exclusions.status}' for this CVE, This will be whitelisted.",
                extra_tags="alert-success")
            relative_url = reverse("finding_exclusion", args=[str(duplicate_finding_exclusions.pk)])
            engagement_ids = duplicate_finding_exclusions.engagements.values_list('id', flat=True)
            add_findings_to_whitelist.apply_async(
                args=(
                    duplicate_finding_exclusions.unique_id_from_tool,
                    relative_url,
                    list(engagement_ids),
                    [duplicate_finding_exclusions.product.id] if duplicate_finding_exclusions.product else []
                )
            )
            
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
        }, user=request.user)

    finding_exclusion = None

    if request.method == "POST":
        form = CreateFindingExclusionForm(user=request.user, data=request.POST)
        list_type = request.POST.get(key="type")    
        
        if form.is_valid():
            exclusion: FindingExclusion = form.save(commit=False)
            exclusion.practice = default_practice
            exclusion.created_by = request.user
            if list_type == "black_list":
                if not is_in_group(request.user, Constants.REVIEWERS_MAINTAINER_GROUP.value):
                    raise PermissionDenied
                
                previous_status = exclusion.status
                exclusion.status = "Accepted"
                exclusion.final_status = "Accepted"
                exclusion.accepted_at = timezone.now()
                exclusion.accepted_by = request.user
                exclusion.status_updated_at = timezone.now()
                exclusion.status_updated_by = request.user
                exclusion.save()
                
                FindingExclusionLog.objects.create(
                    finding_exclusion=exclusion,
                    changed_by=request.user,
                    previous_status=previous_status,
                    current_status="Accepted"
                )
                
                relative_url = reverse("finding_exclusion", args=[str(exclusion.pk)])
                add_findings_to_blacklist.apply_async(args=(exclusion.unique_id_from_tool, relative_url,))
            else:  
                exclusion.save()
                form.save_m2m()
                
                cve = request.POST.get(key="unique_id_from_tool")
                
                reviewers = get_reviewers_members()
                
                create_notification(
                    event="finding_exclusion_request",
                    subject=f"🙋‍♂️New {list_type} Request for the CVE: {cve} 🙏",
                    title=f"A new request has been created to add {cve} to the {list_type}.",
                    description=f"A new request has been created to add {cve} to the {list_type}.",
                    url=reverse("finding_exclusion", args=[str(exclusion.pk)]),
                    recipients=reviewers,
                    icon="check-circle",
                    color_icon="#28a745"
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


def delete_finding_exclusion_discussion(request: HttpRequest, fxid: str, did: str) -> HttpResponse:
    """Delete a discussion for an finding exclusion

    Args:
        request (HttpRequest): Http request object
        fxid (str): Finding exclusion ID
        discussion_id (str): Discussion ID

    Returns:
        HttpResponse: Http response object via Django template
    """
    discussion = get_object_or_404(FindingExclusionDiscussion, pk=did)
    discussion.delete()
    
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
        
    if not has_valid_comments(finding_exclusion, request.user):
        messages.add_message(
            request,
            messages.ERROR,
            "A comment must be added before marking as reviewed.",
            extra_tags="alert-danger")
        return redirect('finding_exclusion', fxid=fxid)
    
    previous_status = finding_exclusion.status
    finding_exclusion.status = "Reviewed"
    finding_exclusion.reviewed_at = datetime.now()
    finding_exclusion.reviewed_by = request.user
    finding_exclusion.status_updated_at = datetime.now()
    finding_exclusion.status_updated_by = request.user
    finding_exclusion.save()
    
    FindingExclusionLog.objects.create(
        finding_exclusion=finding_exclusion,
        changed_by=request.user,
        previous_status=previous_status,
        current_status="Reviewed"
    )
    
    create_notification(event="finding_exclusion_request",
                        subject=f"✅Review applied to the whitelisting request - {finding_exclusion.unique_id_from_tool}",
                        title=f"Review applied to the whitelisting request - {finding_exclusion.unique_id_from_tool}",
                        description=f"Review applied to the whitelisting request - {finding_exclusion.unique_id_from_tool}, You will be notified of the final result.",
                        url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
                        recipients=[finding_exclusion.created_by.username],
                        icon="check-circle",
                        color_icon="#28a745")
    
    message = f"Eligibility Assessment Vulnerability Whitelist - {finding_exclusion.unique_id_from_tool}"
    
    send_mail_to_cybersecurity(finding_exclusion, message)
    
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
            
            if not has_valid_comments(finding_exclusion, request.user):
                messages.add_message(
                    request,
                    messages.ERROR,
                    "A comment must be added before accepting.",
                    extra_tags="alert-danger")
                return redirect('finding_exclusion', fxid=fxid)
            
            previous_status = finding_exclusion.status
            finding_exclusion.status = "Accepted"
            finding_exclusion.final_status = "Accepted"
            finding_exclusion.accepted_at = timezone.now()
            finding_exclusion.accepted_by = request.user
            finding_exclusion.status_updated_at = timezone.now()
            finding_exclusion.status_updated_by = request.user
            finding_exclusion.expiration_date = timezone.now() + timedelta(days=int(settings.FINDING_EXCLUSION_EXPIRATION_DAYS))
            finding_exclusion.save()
            
            FindingExclusionLog.objects.create(
                finding_exclusion=finding_exclusion,
                changed_by=request.user,
                previous_status=previous_status,
                current_status="Accepted"
            )
            
            relative_url = reverse("finding_exclusion", args=[str(finding_exclusion.pk)])
            engagement_ids = finding_exclusion.engagements.values_list('id', flat=True)
            add_findings_to_whitelist.apply_async(
                args=(
                    finding_exclusion.unique_id_from_tool,
                    str(relative_url),
                    list(engagement_ids),
                    [finding_exclusion.product.id] if finding_exclusion.product else []
                )
            )
                    
    except Exception as e:
        messages.add_message(
                request,
                messages.ERROR,
                f"An error occurred while accepting this finding exclusion, please try again later. Details: {e.with_traceback()}",
                extra_tags="alert-success")
        return redirect('finding_exclusion', fxid=fxid)
    
    maintainers = get_reviewers_members()
    
    create_notification(event="finding_exclusion_approved",
                        subject=f"✅Whitelisting request accepted - {finding_exclusion.unique_id_from_tool}",
                        title=f"Whitelisting request accepted - {finding_exclusion.unique_id_from_tool}",
                        description=f"Whitelisting request accepted - {finding_exclusion.unique_id_from_tool}",
                        url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
                        recipients=[finding_exclusion.created_by.username] + maintainers,
                        icon="check-circle",
                        color_icon="#28a745")
    
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
    
    if not has_valid_comments(finding_exclusion, request.user):
        messages.add_message(
            request,
            messages.ERROR,
            "A comment must be added before rejecting.",
            extra_tags="alert-danger")
        return redirect('finding_exclusion', fxid=fxid)
    
    previous_status = finding_exclusion.status
    finding_exclusion.status = "Rejected"
    finding_exclusion.final_status = "Rejected"
    finding_exclusion.rejected_by = request.user
    finding_exclusion.status_updated_at = datetime.now()
    finding_exclusion.status_updated_by = request.user
    
    # Mark as reviewed
    if not finding_exclusion.reviewed_at:
        finding_exclusion.reviewed_at = datetime.now()
        finding_exclusion.reviewed_by = request.user
    finding_exclusion.save()
    
    FindingExclusionLog.objects.create(
        finding_exclusion=finding_exclusion,
        changed_by=request.user,
        previous_status=previous_status,
        current_status="Rejected"
    )

    maintainers = get_reviewers_members()
    
    create_notification(
        event="finding_exclusion_rejected",
        subject=f"❌Whitelisting request rejected - {finding_exclusion.unique_id_from_tool}",
        title=f"Whitelisting request rejected - {finding_exclusion.unique_id_from_tool}",
        description=f"Whitelisting request rejected - {finding_exclusion.unique_id_from_tool}.",
        url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
        recipients=[finding_exclusion.created_by.username] + maintainers,
        icon="xmark-circle",
        color_icon="#FA0101"
    )
    
    messages.add_message(
            request,
            messages.SUCCESS,
            "Finding Exclusion rejected.",
            extra_tags="alert-success")
        
    return redirect('finding_exclusion', fxid=fxid)
    
            
def expire_finding_exclusion_request(request: HttpRequest, fxid: str) -> HttpResponse:
    if not is_in_reviewer_group(request.user) and \
        not is_in_group(request.user, Constants.APPROVERS_CYBERSECURITY_GROUP.value):
        raise PermissionDenied
    finding_exclusion = get_object_or_404(FindingExclusion, uuid=fxid)
    
    previous_status = finding_exclusion.status
    expire_finding_exclusion_immediately.apply_async(args=(str(finding_exclusion.uuid),))
    
    FindingExclusionLog.objects.create(
        finding_exclusion=finding_exclusion,
        changed_by=request.user,
        previous_status=previous_status,
        current_status="Expired"
    )

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
        form = EditFindingExclusionForm(data=request.POST, instance=finding_exclusion, user=request.user)
        if form.is_valid():
            form.save()
            
            messages.add_message(
                request,
                messages.SUCCESS,
                "Finding Exclusion updated.",
                extra_tags="alert-success"
            )
            
            return redirect('finding_exclusion', fxid=fxid)
    else:
        form = EditFindingExclusionForm(instance=finding_exclusion, user=request.user)

    return render(request, 'dojo/edit_finding_exclusion.html', {'form': form})


def edit_finding_exclusion_request(request: HttpRequest, fxid: str) -> HttpResponse:
    if not is_in_group(request.user, Constants.REVIEWERS_MAINTAINER_GROUP.value):
        raise PermissionDenied
    
    return redirect('edit_finding_exclusion', fxid=fxid)
        

def delete_finding_exclusion(request: HttpRequest, fxid: str) -> HttpResponse:
    if not is_in_group(request.user, Constants.REVIEWERS_MAINTAINER_GROUP.value):
        raise PermissionDenied
    
    finding_exclusion = get_object_or_404(FindingExclusion, uuid=fxid)
    remove_findings_from_deleted_finding_exclusions.apply_async(
        args=(
            finding_exclusion.unique_id_from_tool,
            finding_exclusion.type,
            list(finding_exclusion.engagements.values_list('id', flat=True)),
            [finding_exclusion.product.id] if finding_exclusion.product else []
        )
    )
    finding_exclusion.delete()
    
    messages.add_message(
            request,
            messages.SUCCESS,
            "Finding Exclusion deleted.",
            extra_tags="alert-success")
    
    return redirect('finding_exclusions')


def reopen_finding_exclusion_request(request: HttpRequest, fxid: str) -> HttpResponse:
    if not is_in_group(request.user, Constants.REVIEWERS_MAINTAINER_GROUP.value) and \
        not is_in_group(request.user, Constants.APPROVERS_CYBERSECURITY_GROUP.value):
        raise PermissionDenied
    
    finding_exclusion = get_object_or_404(FindingExclusion, uuid=fxid)
    
    previous_status = finding_exclusion.status
    finding_exclusion.status = "Accepted"
    finding_exclusion.final_status = "Accepted"
    finding_exclusion.status_updated_at = datetime.now()
    finding_exclusion.status_updated_by = request.user
    finding_exclusion.reviewed_at = datetime.now()
    finding_exclusion.reviewed_by = request.user
    finding_exclusion.save()
    
    FindingExclusionLog.objects.create(
        finding_exclusion=finding_exclusion,
        changed_by=request.user,
        previous_status=previous_status,
        current_status="Accepted"
    )

    relative_url = reverse("finding_exclusion", args=[str(finding_exclusion.pk)])
    engagement_ids = finding_exclusion.engagements.values_list('id', flat=True)
    add_findings_to_whitelist.apply_async(
        args=(
            finding_exclusion.unique_id_from_tool,
            str(relative_url),
            list(engagement_ids),
            [finding_exclusion.product.id] if finding_exclusion.product else []
        )
    )
    
    messages.add_message(
            request,
            messages.SUCCESS,
            "Finding Exclusion reopened.",
            extra_tags="alert-success")
        
    return redirect('finding_exclusion', fxid=fxid)


def orphans_reclassification(request: HttpRequest) -> HttpResponse:
    system_settings = System_Settings.objects.get()
    orphan_product_type_name = system_settings.orphan_findings
    
    if not has_permission_to_reclassify_orphans(request.user):
        raise PermissionDenied
    
    orphans_product_type = Product_Type.objects.filter(name=orphan_product_type_name).first()
    
    search_query = request.GET.get('search', '').strip()
    
    orphan_products = Product.objects.filter(
        prod_type=orphans_product_type
    ).order_by('name')
    
    if search_query:
        orphan_products = orphan_products.filter(name__icontains=search_query)
    
    page_obj = get_page_items(request, orphan_products, 100)
    
    product_types = Product_Type.objects.exclude(name=orphan_product_type_name).order_by('name')
    
    context = {
        "orphan_products": page_obj,
        "product_types": product_types,
        "name": "Reclassification of Orphans",
        "page_obj": page_obj,
    }
    
    add_breadcrumb(title="Reclassification of Orphans", top_level=True, request=request)
    return render(request, "dojo/views_orphans_reclassification.html", context)


def reclassify_orphan_products(request: HttpRequest) -> HttpResponse:
    system_settings = System_Settings.objects.get()
    orphan_product_type_name = system_settings.orphan_findings
    
    if not has_permission_to_reclassify_orphans(request.user):
        raise PermissionDenied

    data = request.POST
    product_type_id = data.get('product_type')
    selected_orphan_products = data.getlist('selected_products')

    product_type = get_object_or_404(Product_Type, pk=product_type_id)

    Product.objects.filter(
        prod_type__name=orphan_product_type_name,
        id__in=selected_orphan_products
    ).update(prod_type=product_type)

    products = Product.objects.filter(id__in=selected_orphan_products)
    for p in products:
        current_tags = list(p.tags.get_tag_list())
        if 'identified_by_orphan_reclassification' not in current_tags:
            current_tags.append('identified_by_orphan_reclassification')
            p.tags.set(current_tags)
            p.save()

    messages.add_message(
        request,
        messages.SUCCESS,
        f"{len(selected_orphan_products)} products reclassified to '{product_type.name}'.",
        extra_tags="alert-success"
    )

    return redirect('orphans_reclassification')


@method_decorator(csrf_exempt, name='dispatch')
class ExcelReclassificationView(View):
    def post(self, request: HttpRequest) -> HttpResponse:
        if request.FILES.get('excel_file'):
            return self.process_excel_file(request)
        return redirect('orphans_reclassification')
    
    def process_excel_file(self, request):
        excel_file = request.FILES['excel_file']
        
        try:
            df = pd.read_excel(excel_file, usecols=['Product', 'ProductType'])
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': f"Error reading Excel file: {e}"
            })
        
        if 'Product' not in df.columns or 'ProductType' not in df.columns:
            return JsonResponse({
                'status': 'error',
                'message': "Excel file must contain 'Product' and 'ProductType' columns."
            })
        
        max_records = 100000
        if len(df) > max_records:
            df = df.head(max_records)
        
        df = df.dropna().drop_duplicates()
        
        session_key = f"excel_processing_{request.session.session_key}"
        products_to_process = []
        
        for _, row in df.iterrows():
            products_to_process.append({
                'product_name': str(row['Product']).strip(),
                'product_type_name': str(row['ProductType']).strip(),
                'status': 'pending'
            })
        
        request.session[session_key] = {
            'total': len(products_to_process),
            'processed': 0,
            'successful': 0,
            'failed': 0,
            'products': products_to_process
        }
        
        return JsonResponse({
            'status': 'started',
            'total': len(products_to_process),
            'session_key': session_key,
            'message': f'Processing started for {len(products_to_process)} products.'
        })


def get_processing_status(request):
    if not has_permission_to_reclassify_orphans(request.user):
        raise PermissionDenied

    session_key = request.GET.get('session_key')
    if not session_key or session_key not in request.session:
        return JsonResponse({'status': 'not_found'})
    
    progress_data = request.session[session_key]
    return JsonResponse(progress_data)


@csrf_exempt
def process_batch(request):
    system_settings = System_Settings.objects.get()
    orphan_product_type_name = system_settings.orphan_findings
    
    if not has_permission_to_reclassify_orphans(request.user):
        raise PermissionDenied

    if request.method == 'POST':
        data = json.loads(request.body)
        session_key = data.get('session_key')
        batch_size = data.get('batch_size', 100)

        if not session_key or session_key not in request.session:
            return JsonResponse({'status': 'error', 'message': 'Session not found'})

        progress_data = request.session[session_key]

        start_index = progress_data['processed']
        end_index = min(start_index + batch_size, progress_data['total'])

        if start_index >= end_index:
            return JsonResponse({
                'status': 'completed',
                'processed': progress_data['processed'],
                'total': progress_data['total'],
                'successful': progress_data['successful'],
                'failed': progress_data['failed'],
                'completed': True
            })

        batch_products = progress_data['products'][start_index:end_index]

        product_names = [p['product_name'] for p in batch_products]
        product_type_names = list(set([p['product_type_name'] for p in batch_products]))

        products_qs = Product.objects.filter(
            name__in=product_names,
            prod_type__name=orphan_product_type_name
        ).select_related('prod_type')

        product_types_qs = Product_Type.objects.filter(name__in=product_type_names)

        products_dict = {p.name: p for p in products_qs}
        product_types_dict = {pt.name: pt for pt in product_types_qs}

        products_to_update = []
        successful_updates = 0

        for product_data in batch_products:
            product_name = product_data['product_name']
            product_type_name = product_data['product_type_name']

            product = products_dict.get(product_name)
            product_type = product_types_dict.get(product_type_name)

            if product and product_type:
                product.prod_type = product_type
                products_to_update.append(product)

                product_data['status'] = 'success'
                successful_updates += 1
            else:
                product_data['status'] = 'failed'
                if not product:
                    product_data['error'] = "Product not found or not an orphan"
                else:
                    product_data['error'] = "ProductType not found"

        if products_to_update:
            Product.objects.bulk_update(products_to_update, ['prod_type'])

            for product in products_to_update:
                current_tags = set(product.tags.get_tag_list())
                if 'identified_by_orphan_reclassification' not in current_tags:
                    product.tags.add('identified_by_orphan_reclassification')

                product.save()

        failed_updates = len(batch_products) - successful_updates
        progress_data['processed'] = end_index
        progress_data['successful'] += successful_updates
        progress_data['failed'] += failed_updates

        request.session[session_key] = progress_data
        request.session.modified = True

        return JsonResponse({
            'status': 'processing',
            'processed': progress_data['processed'],
            'total': progress_data['total'],
            'successful': progress_data['successful'],
            'failed': progress_data['failed'],
            'completed': progress_data['processed'] >= progress_data['total'],
            'batch_size': len(batch_products)
        })


def export_orphan_products_simple(request):
    system_settings = System_Settings.objects.get()
    orphan_product_type_name = system_settings.orphan_findings
    
    if not has_permission_to_reclassify_orphans(request.user):
        raise PermissionDenied

    orphan_products = Product.objects.filter(prod_type__name=orphan_product_type_name)
    
    search_query = request.GET.get('search', '')
    if search_query:
        orphan_products = orphan_products.filter(
            Q(name__icontains=search_query) |
            Q(code__icontains=search_query)
        )
    
    data = [{'Product': product.name, 'ProductType': ''} for product in orphan_products]
    
    df = pd.DataFrame(data) 
    
    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename="plantilla_reclasificacion.xlsx"'
    
    with pd.ExcelWriter(response, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Plantilla', index=False)
        
        worksheet = writer.sheets['Plantilla']
        worksheet.column_dimensions['A'].width = 50
        worksheet.column_dimensions['B'].width = 30
        
        for cell in worksheet[1]:
            cell.font = Font(bold=True)
            cell.fill = PatternFill(start_color="E6E6E6", end_color="E6E6E6", fill_type="solid")
    
    return response
