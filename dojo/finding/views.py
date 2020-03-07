# #  findings
import base64
import json
import logging
import mimetypes
import os
import shutil

from collections import OrderedDict
from django.db import models
from django.db.models.functions import Length
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied, ValidationError
from django.core import serializers
from django.urls import reverse
from django.http import Http404, HttpResponse
from django.http import HttpResponseRedirect, HttpResponseForbidden
from django.http import StreamingHttpResponse
from django.shortcuts import render, get_object_or_404
from django.utils import formats
from django.utils.safestring import mark_safe
from django.utils import timezone
from django.views.decorators.http import require_POST
from tagging.models import Tag
from itertools import chain

from dojo.filters import OpenFindingFilter, \
    OpenFingingSuperFilter, AcceptedFingingSuperFilter, \
    ClosedFingingSuperFilter, TemplateFindingFilter
from dojo.forms import NoteForm, FindingNoteForm, CloseFindingForm, FindingForm, PromoteFindingForm, FindingTemplateForm, \
    DeleteFindingTemplateForm, FindingImageFormSet, JIRAFindingForm, ReviewFindingForm, ClearFindingReviewForm, \
    DefectFindingForm, StubFindingForm, DeleteFindingForm, DeleteStubFindingForm, ApplyFindingTemplateForm, \
    FindingFormID, FindingBulkUpdateForm, MergeFindings
from dojo.models import Product_Type, Finding, Notes, NoteHistory, Note_Type, \
    Risk_Acceptance, BurpRawRequestResponse, Stub_Finding, Endpoint, Finding_Template, FindingImage, \
    FindingImageAccessToken, JIRA_Issue, JIRA_PKey, Dojo_User, Cred_Mapping, Test, Product, User, Engagement
from dojo.utils import get_page_items, add_breadcrumb, FileIterWrapper, process_notifications, \
    add_comment, jira_get_resolution_id, jira_change_resolution_id, get_jira_connection, \
    get_system_setting, create_notification, apply_cwe_to_template, Product_Tab, calculate_grade, log_jira_alert

from dojo.tasks import add_issue_task, update_issue_task, add_comment_task
from django.template.defaultfilters import pluralize
from django.db.models.query import QuerySet


logger = logging.getLogger(__name__)


def verified_findings(request, pid=None, eid=None, view=None):
    show_product_column = True
    title = None
    custom_breadcrumb = None
    filter_name = "Verified"
    pid_local = None
    tags = Tag.objects.usage_for_model(Finding)
    if pid:
        if view == "All":
            filter_name = "All"
            findings = Finding.objects.filter(test__engagement__product__id=pid).order_by('numerical_severity')
        else:
            findings = Finding.objects.filter(test__engagement__product__id=pid, verified=True).order_by('numerical_severity')
    elif eid:
        eng = get_object_or_404(Engagement, id=eid)
        pid_local = eng.product.id
        if view == "All":
            filter_name = "All"
            findings = Finding.objects.filter(test__engagement=eid).order_by('numerical_severity')
        else:
            findings = Finding.objects.filter(test__engagement=eid, verified=True).order_by('numerical_severity')
    else:
        if view == "All":
            filter_name = "All"
            findings = Finding.objects.all().order_by('numerical_severity')
        else:
            findings = Finding.objects.filter(verified=True).order_by('numerical_severity')

    if request.user.is_staff:
        findings = OpenFingingSuperFilter(
            request.GET, queryset=findings, user=request.user, pid=pid)
    else:
        findings = findings.filter(
            test__engagement__product__authorized_users__in=[request.user])
        findings = OpenFindingFilter(
            request.GET, queryset=findings, user=request.user, pid=pid)

    title_words = [
        word for finding in findings.qs for word in finding.title.split()
        if len(word) > 2
    ]

    title_words = sorted(set(title_words))
    paged_findings = get_page_items(request, findings.qs, 25)

    product_type = None
    if 'test__engagement__product__prod_type' in request.GET:
        p = request.GET.getlist('test__engagement__product__prod_type', [])
        if len(p) == 1:
            product_type = get_object_or_404(Product_Type, id=p[0])

    endpoint = None
    if 'endpoints' in request.GET:
        endpoints = request.GET.getlist('endpoints', [])
        if len(endpoints) == 1:
            endpoint = endpoints[0]
            endpoint = get_object_or_404(Endpoint, id=endpoint)
            pid = endpoint.product.id
            title = "Vulnerable Endpoints"
            custom_breadcrumb = OrderedDict([("Endpoints", reverse('vulnerable_endpoints')), (endpoint, reverse('view_endpoint', args=(endpoint.id, )))])

    found_by = None
    try:
        found_by = findings.found_by.all().distinct()
    except:
        found_by = None
        pass

    product_tab = None
    active_tab = None
    jira_config = None

    # Only show product tab view in product or engagement
    if pid:
        show_product_column = False
        product_tab = Product_Tab(pid, title="Findings", tab="findings")
        jira_config = JIRA_PKey.objects.filter(product=pid).first()
    elif eid and pid_local:
        show_product_column = False
        product_tab = Product_Tab(pid_local, title=eng.name, tab="engagements")
        jira_config = JIRA_PKey.objects.filter(product__engagement=eid).first()
    else:
        add_breadcrumb(title="Findings", top_level=not len(request.GET), request=request)
    if jira_config:
        jira_config = jira_config.conf_id

    paged_findings.object_list = prefetch_for_findings(paged_findings.object_list)

    return render(
        request, 'dojo/findings_list.html', {
            'show_product_column': show_product_column,
            "product_tab": product_tab,
            "findings": paged_findings,
            "filtered": findings,
            "title_words": title_words,
            'found_by': found_by,
            'custom_breadcrumb': custom_breadcrumb,
            'filter_name': filter_name,
            'title': title,
            'tag_input': tags,
            'jira_config': jira_config,
        })


def out_of_scope_findings(request, pid=None, eid=None, view=None):
    show_product_column = True
    title = None
    custom_breadcrumb = None
    filter_name = "Out of scope"
    pid_local = None
    tags = Tag.objects.usage_for_model(Finding)
    if pid:
        if view == "All":
            filter_name = "All"
            findings = Finding.objects.filter(test__engagement__product__id=pid).order_by('numerical_severity')
        else:
            findings = Finding.objects.filter(test__engagement__product__id=pid, out_of_scope=True).order_by('numerical_severity')
    elif eid:
        eng = get_object_or_404(Engagement, id=eid)
        pid_local = eng.product.id
        if view == "All":
            filter_name = "All"
            findings = Finding.objects.filter(test__engagement=eid).order_by('numerical_severity')
        else:
            findings = Finding.objects.filter(test__engagement=eid, out_of_scope=True).order_by('numerical_severity')
    else:
        if view == "All":
            filter_name = "All"
            findings = Finding.objects.all().order_by('numerical_severity')
        else:
            findings = Finding.objects.filter(active=False, out_of_scope=True).order_by('numerical_severity')

    if request.user.is_staff:
        findings = OpenFingingSuperFilter(
            request.GET, queryset=findings, user=request.user, pid=pid)
    else:
        findings = findings.filter(
            test__engagement__product__authorized_users__in=[request.user])
        findings = OpenFindingFilter(
            request.GET, queryset=findings, user=request.user, pid=pid)

    title_words = [
        word for finding in findings.qs for word in finding.title.split()
        if len(word) > 2
    ]

    title_words = sorted(set(title_words))
    paged_findings = get_page_items(request, findings.qs, 25)

    product_type = None
    if 'test__engagement__product__prod_type' in request.GET:
        p = request.GET.getlist('test__engagement__product__prod_type', [])
        if len(p) == 1:
            product_type = get_object_or_404(Product_Type, id=p[0])

    endpoint = None
    if 'endpoints' in request.GET:
        endpoints = request.GET.getlist('endpoints', [])
        if len(endpoints) == 1:
            endpoint = endpoints[0]
            endpoint = get_object_or_404(Endpoint, id=endpoint)
            pid = endpoint.product.id
            title = "Vulnerable Endpoints"
            custom_breadcrumb = OrderedDict([("Endpoints", reverse('vulnerable_endpoints')), (endpoint, reverse('view_endpoint', args=(endpoint.id, )))])

    found_by = None
    try:
        found_by = findings.found_by.all().distinct()
    except:
        found_by = None
        pass

    product_tab = None
    active_tab = None
    jira_config = None

    # Only show product tab view in product or engagement
    if pid:
        show_product_column = False
        product_tab = Product_Tab(pid, title="Findings", tab="findings")
        jira_config = JIRA_PKey.objects.filter(product=pid).first()
    elif eid and pid_local:
        show_product_column = False
        product_tab = Product_Tab(pid_local, title=eng.name, tab="engagements")
        jira_config = JIRA_PKey.objects.filter(product__engagement=eid).first()
    else:
        add_breadcrumb(title="Findings", top_level=not len(request.GET), request=request)
    if jira_config:
        jira_config = jira_config.conf_id

    paged_findings.object_list = prefetch_for_findings(paged_findings.object_list)

    return render(
        request, 'dojo/findings_list.html', {
            'show_product_column': show_product_column,
            "product_tab": product_tab,
            "findings": paged_findings,
            "filtered": findings,
            "title_words": title_words,
            'found_by': found_by,
            'custom_breadcrumb': custom_breadcrumb,
            'filter_name': filter_name,
            'title': title,
            'tag_input': tags,
            'jira_config': jira_config,
        })


def false_positive_findings(request, pid=None, eid=None, view=None):
    show_product_column = True
    title = None
    custom_breadcrumb = None
    filter_name = "False Positive"
    pid_local = None
    tags = Tag.objects.usage_for_model(Finding)
    if pid:
        if view == "All":
            filter_name = "All"
            findings = Finding.objects.filter(test__engagement__product__id=pid).order_by('numerical_severity')
        else:
            findings = Finding.objects.filter(test__engagement__product__id=pid, duplicate=False, active=False, false_p=True).order_by('numerical_severity')
    elif eid:
        eng = get_object_or_404(Engagement, id=eid)
        pid_local = eng.product.id
        if view == "All":
            filter_name = "All"
            findings = Finding.objects.filter(test__engagement=eid).order_by('numerical_severity')
        else:
            findings = Finding.objects.filter(test__engagement=eid, duplicate=False, active=False, false_p=True).order_by('numerical_severity')
    else:
        if view == "All":
            filter_name = "All"
            findings = Finding.objects.all().order_by('numerical_severity')
        else:
            findings = Finding.objects.filter(active=False, duplicate=False, false_p=True).order_by('numerical_severity')

    if request.user.is_staff:
        findings = OpenFingingSuperFilter(
            request.GET, queryset=findings, user=request.user, pid=pid)
    else:
        findings = findings.filter(
            test__engagement__product__authorized_users__in=[request.user])
        findings = OpenFindingFilter(
            request.GET, queryset=findings, user=request.user, pid=pid)

    title_words = [
        word for finding in findings.qs for word in finding.title.split()
        if len(word) > 2
    ]

    title_words = sorted(set(title_words))
    paged_findings = get_page_items(request, findings.qs, 25)

    product_type = None
    if 'test__engagement__product__prod_type' in request.GET:
        p = request.GET.getlist('test__engagement__product__prod_type', [])
        if len(p) == 1:
            product_type = get_object_or_404(Product_Type, id=p[0])

    endpoint = None
    if 'endpoints' in request.GET:
        endpoints = request.GET.getlist('endpoints', [])
        if len(endpoints) == 1:
            endpoint = endpoints[0]
            endpoint = get_object_or_404(Endpoint, id=endpoint)
            pid = endpoint.product.id
            title = "Vulnerable Endpoints"
            custom_breadcrumb = OrderedDict([("Endpoints", reverse('vulnerable_endpoints')), (endpoint, reverse('view_endpoint', args=(endpoint.id, )))])

    found_by = None
    try:
        found_by = findings.found_by.all().distinct()
    except:
        found_by = None
        pass

    product_tab = None
    active_tab = None
    jira_config = None

    # Only show product tab view in product or engagement
    if pid:
        show_product_column = False
        product_tab = Product_Tab(pid, title="Findings", tab="findings")
        jira_config = JIRA_PKey.objects.filter(product=pid).first()
    elif eid and pid_local:
        show_product_column = False
        product_tab = Product_Tab(pid_local, title=eng.name, tab="engagements")
        jira_config = JIRA_PKey.objects.filter(product__engagement=eid).first()
    else:
        add_breadcrumb(title="Findings", top_level=not len(request.GET), request=request)
    if jira_config:
        jira_config = jira_config.conf_id

    paged_findings.object_list = prefetch_for_findings(paged_findings.object_list)

    return render(
        request, 'dojo/findings_list.html', {
            'show_product_column': show_product_column,
            "product_tab": product_tab,
            "findings": paged_findings,
            "filtered": findings,
            "title_words": title_words,
            'found_by': found_by,
            'custom_breadcrumb': custom_breadcrumb,
            'filter_name': filter_name,
            'title': title,
            'tag_input': tags,
            'jira_config': jira_config,
        })


def inactive_findings(request, pid=None, eid=None, view=None):
    show_product_column = True
    title = None
    custom_breadcrumb = None
    filter_name = "Inactive"
    pid_local = None
    tags = Tag.objects.usage_for_model(Finding)
    if pid:
        if view == "All":
            filter_name = "All"
            findings = Finding.objects.filter(test__engagement__product__id=pid).order_by('numerical_severity')
        else:
            findings = Finding.objects.filter(test__engagement__product__id=pid, active=False, duplicate=False).order_by('numerical_severity')
    elif eid:
        eng = get_object_or_404(Engagement, id=eid)
        pid_local = eng.product.id
        if view == "All":
            filter_name = "All"
            findings = Finding.objects.filter(test__engagement=eid).order_by('numerical_severity')
        else:
            findings = Finding.objects.filter(test__engagement=eid, active=False, duplicate=False).order_by('numerical_severity')
    else:
        if view == "All":
            filter_name = "All"
            findings = Finding.objects.all().order_by('numerical_severity')
        else:
            findings = Finding.objects.filter(active=False, duplicate=False).order_by('numerical_severity')

    if request.user.is_staff:
        findings = OpenFingingSuperFilter(
            request.GET, queryset=findings, user=request.user, pid=pid)
    else:
        findings = findings.filter(
            test__engagement__product__authorized_users__in=[request.user])
        findings = OpenFindingFilter(
            request.GET, queryset=findings, user=request.user, pid=pid)

    title_words = [
        word for finding in findings.qs for word in finding.title.split()
        if len(word) > 2
    ]

    title_words = sorted(set(title_words))
    paged_findings = get_page_items(request, findings.qs, 25)

    product_type = None
    if 'test__engagement__product__prod_type' in request.GET:
        p = request.GET.getlist('test__engagement__product__prod_type', [])
        if len(p) == 1:
            product_type = get_object_or_404(Product_Type, id=p[0])

    endpoint = None
    if 'endpoints' in request.GET:
        endpoints = request.GET.getlist('endpoints', [])
        if len(endpoints) == 1:
            endpoint = endpoints[0]
            endpoint = get_object_or_404(Endpoint, id=endpoint)
            pid = endpoint.product.id
            title = "Vulnerable Endpoints"
            custom_breadcrumb = OrderedDict([("Endpoints", reverse('vulnerable_endpoints')), (endpoint, reverse('view_endpoint', args=(endpoint.id, )))])

    found_by = None
    try:
        found_by = findings.found_by.all().distinct()
    except:
        found_by = None
        pass

    product_tab = None
    active_tab = None
    jira_config = None

    # Only show product tab view in product or engagement
    if pid:
        show_product_column = False
        product_tab = Product_Tab(pid, title="Findings", tab="findings")
        jira_config = JIRA_PKey.objects.filter(product=pid).first()
    elif eid and pid_local:
        show_product_column = False
        product_tab = Product_Tab(pid_local, title=eng.name, tab="engagements")
        jira_config = JIRA_PKey.objects.filter(product__engagement=eid).first()
    else:
        add_breadcrumb(title="Findings", top_level=not len(request.GET), request=request)
    if jira_config:
        jira_config = jira_config.conf_id

    paged_findings.object_list = prefetch_for_findings(paged_findings.object_list)

    return render(
        request, 'dojo/findings_list.html', {
            'show_product_column': show_product_column,
            "product_tab": product_tab,
            "findings": paged_findings,
            "filtered": findings,
            "title_words": title_words,
            'found_by': found_by,
            'custom_breadcrumb': custom_breadcrumb,
            'filter_name': filter_name,
            'title': title,
            'tag_input': tags,
            'jira_config': jira_config,
        })


def open_findings(request, pid=None, eid=None, view=None):
    show_product_column = True
    title = None
    custom_breadcrumb = None
    filter_name = "Open"
    pid_local = None
    tags = Tag.objects.usage_for_model(Finding)
    if pid:
        if view == "All":
            filter_name = "All"
            findings = Finding.objects.filter(test__engagement__product__id=pid).order_by('numerical_severity')
        else:
            findings = Finding.objects.filter(test__engagement__product__id=pid, active=True, duplicate=False).order_by('numerical_severity')
    elif eid:
        eng = get_object_or_404(Engagement, id=eid)
        pid_local = eng.product.id
        if view == "All":
            filter_name = "All"
            findings = Finding.objects.filter(test__engagement=eid).order_by('numerical_severity')
        else:
            findings = Finding.objects.filter(test__engagement=eid, active=True, duplicate=False).order_by('numerical_severity')
    else:
        if view == "All":
            filter_name = "All"
            findings = Finding.objects.all().order_by('numerical_severity')
        else:
            findings = Finding.objects.filter(active=True, duplicate=False).order_by('numerical_severity')

    if not request.user.is_staff:
        findings = findings.filter(
            test__engagement__product__authorized_users__in=[request.user])

    title_words = [
        word for finding in findings for word in finding.title.split()
        if len(word) > 2
    ]
    title_words = sorted(set(title_words))

    if request.user.is_staff:
        findings_filter = OpenFingingSuperFilter(
            request.GET, queryset=findings, user=request.user, pid=pid)
    else:
        findings_filter = OpenFindingFilter(
            request.GET, queryset=findings, user=request.user, pid=pid)

    paged_findings = get_page_items(request, findings_filter.qs, 25)

    product_type = None
    if 'test__engagement__product__prod_type' in request.GET:
        p = request.GET.getlist('test__engagement__product__prod_type', [])
        if len(p) == 1:
            product_type = get_object_or_404(Product_Type, id=p[0])

    endpoint = None
    if 'endpoints' in request.GET:
        endpoints = request.GET.getlist('endpoints', [])
        if len(endpoints) == 1:
            endpoint = endpoints[0]
            endpoint = get_object_or_404(Endpoint, id=endpoint)
            pid = endpoint.product.id
            title = "Vulnerable Endpoints"
            custom_breadcrumb = OrderedDict([("Endpoints", reverse('vulnerable_endpoints')), (endpoint, reverse('view_endpoint', args=(endpoint.id, )))])

    found_by = None
    try:
        found_by = findings_filter.found_by.all().distinct()
    except:
        found_by = None
        pass

    product_tab = None
    active_tab = None
    jira_config = None

    # Only show product tab view in product or engagement
    if pid:
        show_product_column = False
        product_tab = Product_Tab(pid, title="Findings", tab="findings")
        jira_config = JIRA_PKey.objects.filter(product=pid).first()
    elif eid and pid_local:
        show_product_column = False
        product_tab = Product_Tab(pid_local, title=eng.name, tab="engagements")
        jira_config = JIRA_PKey.objects.filter(product__engagement=eid).first()
    else:
        add_breadcrumb(title="Findings", top_level=not len(request.GET), request=request)
    if jira_config:
        jira_config = jira_config.conf_id

    paged_findings.object_list = prefetch_for_findings(paged_findings.object_list)

    return render(
        request, 'dojo/findings_list.html', {
            'show_product_column': show_product_column,
            "product_tab": product_tab,
            "findings": paged_findings,
            "filtered": findings_filter,
            "title_words": title_words,
            'found_by': found_by,
            'custom_breadcrumb': custom_breadcrumb,
            'filter_name': filter_name,
            'title': title,
            'tag_input': tags,
            'jira_config': jira_config,
        })


def prefetch_for_findings(findings):
    prefetched_findings = findings
    if isinstance(findings, QuerySet):  # old code can arrive here with prods being a list because the query was already executed
        prefetched_findings = prefetched_findings.select_related('reporter')
        prefetched_findings = prefetched_findings.select_related('jira_issue')
        prefetched_findings = prefetched_findings.prefetch_related('test__test_type')
        prefetched_findings = prefetched_findings.prefetch_related('test__engagement__product__jira_pkey_set__conf')
        prefetched_findings = prefetched_findings.prefetch_related('found_by')
        prefetched_findings = prefetched_findings.prefetch_related('risk_acceptance_set')
        # we could try to prefetch only the latest note with SubQuery and OuterRef, but I'm getting that MySql doesn't support limits in subqueries.
        prefetched_findings = prefetched_findings.prefetch_related('notes')
    return prefetched_findings


"""
Accepted findings returns all the accepted findings for all products or a specific product
"""


@user_passes_test(lambda u: u.is_staff)
def accepted_findings(request, pid=None):
    # user = request.user

    findings = Finding.objects.filter(risk_acceptance__isnull=False)
    findings = AcceptedFingingSuperFilter(request.GET, queryset=findings)
    title_words = [
        word for ra in Risk_Acceptance.objects.all() for finding in
        ra.accepted_findings.order_by('title').values('title').distinct()
        for word in finding['title'].split() if len(word) > 2
    ]

    title_words = sorted(set(title_words))
    paged_findings = get_page_items(request, findings.qs, 25)

    product_tab = None
    if pid:
        product_tab = Product_Tab(pid, title="Accepted Findings", tab="findings")

    paged_findings.object_list = prefetch_for_findings(paged_findings.object_list)

    return render(
        request, 'dojo/findings_list.html', {
            "findings": paged_findings,
            "product_tab": product_tab,
            "filter_name": "Accepted",
            "filtered": findings,
            "title_words": title_words,
        })


@user_passes_test(lambda u: u.is_staff)
def closed_findings(request, pid=None):
    findings = Finding.objects.filter(mitigated__isnull=False)
    findings = ClosedFingingSuperFilter(request.GET, queryset=findings)
    title_words = [
        word for finding in findings.qs for word in finding.title.split()
        if len(word) > 2
    ]

    title_words = sorted(set(title_words))
    paged_findings = get_page_items(request, findings.qs.order_by('-mitigated'), 25)

    product_tab = None
    if pid:
        product_tab = Product_Tab(pid, title="Closed Findings", tab="findings")

    paged_findings.object_list = prefetch_for_findings(paged_findings.object_list)

    return render(
        request, 'dojo/findings_list.html', {
            "findings": paged_findings,
            "product_tab": product_tab,
            "filtered": findings,
            "filter_name": "Closed",
            "title_words": title_words,
        })


def view_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    findings = Finding.objects.filter(test=finding.test).order_by('numerical_severity')
    try:
        prev_finding = findings[(list(findings).index(finding)) - 1]
    except AssertionError:
        prev_finding = finding
    try:
        next_finding = findings[(list(findings).index(finding)) + 1]
    except IndexError:
        next_finding = finding
    findings = [finding.id for finding in findings]
    cred_finding = Cred_Mapping.objects.filter(
        finding=finding.id).select_related('cred_id').order_by('cred_id')
    creds = Cred_Mapping.objects.filter(
        test=finding.test.id).select_related('cred_id').order_by('cred_id')
    cred_engagement = Cred_Mapping.objects.filter(
        engagement=finding.test.engagement.id).select_related(
            'cred_id').order_by('cred_id')
    user = request.user
    cwe_template = None
    try:
        cwe_template = Finding_Template.objects.filter(cwe=finding.cwe).first()
    except Finding_Template.DoesNotExist:
        pass

    try:
        jissue = JIRA_Issue.objects.get(finding=finding)
    except:
        jissue = None
        pass
    try:
        jpkey = JIRA_PKey.objects.get(product=finding.test.engagement.product)
        jconf = jpkey.conf
    except:
        jconf = None
        pass
    dojo_user = get_object_or_404(Dojo_User, id=user.id)
    if user.is_staff or user in finding.test.engagement.product.authorized_users.all(
    ):
        pass  # user is authorized for this product
    else:
        raise PermissionDenied

    notes = finding.notes.all()
    note_type_activation = Note_Type.objects.filter(is_active=True).count()
    if note_type_activation:
        available_note_types = find_available_notetypes(notes)
    if request.method == 'POST':
        if note_type_activation:
            form = FindingNoteForm(request.POST, available_note_types=available_note_types)
        else:
            form = NoteForm(request.POST)
        if form.is_valid():
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = timezone.now()
            new_note.save()
            history = NoteHistory(data=new_note.entry,
                                  time=new_note.date,
                                  current_editor=new_note.author)
            history.save()
            new_note.history.add(history)
            finding.notes.add(new_note)
            finding.last_reviewed = new_note.date
            finding.last_reviewed_by = user
            finding.save()
            if jissue is not None:
                add_comment_task(finding, new_note)
            if note_type_activation:
                form = FindingNoteForm(available_note_types=available_note_types)
            else:
                form = NoteForm()
            url = request.build_absolute_uri(
                reverse("view_finding", args=(finding.id, )))
            title = "Finding: " + finding.title
            process_notifications(request, new_note, url, title)
            messages.add_message(
                request,
                messages.SUCCESS,
                'Note saved.',
                extra_tags='alert-success')
            return HttpResponseRedirect(
                reverse('view_finding', args=(finding.id, )))
    else:
        if note_type_activation:
            form = FindingNoteForm(available_note_types=available_note_types)
        else:
            form = NoteForm()

    try:
        reqres = BurpRawRequestResponse.objects.get(finding=finding)
        burp_request = base64.b64decode(reqres.burpRequestBase64)
        burp_response = base64.b64decode(reqres.burpResponseBase64)
    except:
        reqres = None
        burp_request = None
        burp_response = None

    product_tab = Product_Tab(finding.test.engagement.product.id, title="View Finding", tab="findings")
    lastPos = (len(findings)) - 1
    return render(
        request, 'dojo/view_finding.html', {
            'product_tab': product_tab,
            'finding': finding,
            'burp_request': burp_request,
            'jissue': jissue,
            'jconf': jconf,
            'cred_finding': cred_finding,
            'creds': creds,
            'cred_engagement': cred_engagement,
            'burp_response': burp_response,
            'dojo_user': dojo_user,
            'user': user,
            'notes': notes,
            'form': form,
            'cwe_template': cwe_template,
            'found_by': finding.found_by.all().distinct(),
            'findings_list': findings,
            'findings_list_lastElement': findings[lastPos],
            'prev_finding': prev_finding,
            'next_finding': next_finding
        })


@user_passes_test(lambda u: u.is_staff)
def close_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    # in order to close a finding, we need to capture why it was closed
    # we can do this with a Note
    note_type_activation = Note_Type.objects.filter(is_active=True)
    if len(note_type_activation):
        missing_note_types = get_missing_mandatory_notetypes(finding)
    else:
        missing_note_types = note_type_activation
    form = CloseFindingForm(missing_note_types=missing_note_types)
    if request.method == 'POST':
        form = CloseFindingForm(request.POST, missing_note_types=missing_note_types)

        if form.is_valid():
            now = timezone.now()
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = now
            new_note.save()
            finding.notes.add(new_note)

            messages.add_message(
                request,
                messages.SUCCESS,
                'Note Saved.',
                extra_tags='alert-success')

            if len(missing_note_types) == 0:
                finding.active = False
                now = timezone.now()
                finding.mitigated = now
                finding.mitigated_by = request.user
                finding.last_reviewed = finding.mitigated
                finding.last_reviewed_by = request.user
                finding.endpoints.clear()
                finding.save()

                messages.add_message(
                    request,
                    messages.SUCCESS,
                    'Finding closed.',
                    extra_tags='alert-success')
                create_notification(event='other',
                                    title='Closing of %s' % finding.title,
                                    description='The finding "%s" was closed by %s' % (finding.title, request.user),
                                    url=request.build_absolute_uri(reverse('view_test', args=(finding.test.id, ))),
                                    )
                return HttpResponseRedirect(
                    reverse('view_test', args=(finding.test.id, )))
            else:
                return HttpResponseRedirect(
                    reverse('close_finding', args=(finding.id, )))

    else:
        form = CloseFindingForm(missing_note_types=missing_note_types)

    product_tab = Product_Tab(finding.test.engagement.product.id, title="Close", tab="findings")

    return render(request, 'dojo/close_finding.html', {
        'finding': finding,
        'product_tab': product_tab,
        'active_tab': 'findings',
        'user': request.user,
        'form': form,
        'note_types': missing_note_types
    })


@user_passes_test(lambda u: u.is_staff)
def defect_finding_review(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    # in order to close a finding, we need to capture why it was closed
    # we can do this with a Note
    if request.method == 'POST':
        form = DefectFindingForm(request.POST)

        if form.is_valid():
            now = timezone.now()
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = now
            new_note.save()
            finding.notes.add(new_note)
            finding.under_defect_review = False
            defect_choice = form.cleaned_data['defect_choice']

            if defect_choice == "Close Finding":
                finding.active = False
                finding.mitigated = now
                finding.mitigated_by = request.user
                finding.last_reviewed = finding.mitigated
                finding.last_reviewed_by = request.user
                finding.endpoints.clear()

            jira = get_jira_connection(finding)
            if jira and JIRA_Issue.objects.filter(finding=finding).exists():
                j_issue = JIRA_Issue.objects.get(finding=finding)
                issue = jira.issue(j_issue.jira_id)

                if defect_choice == "Close Finding":
                    # If the issue id is closed jira will return Reopen Issue
                    resolution_id = jira_get_resolution_id(jira, issue,
                                                           "Reopen Issue")
                    if resolution_id is None:
                        resolution_id = jira_get_resolution_id(
                            jira, issue, "Resolve Issue")
                        jira_change_resolution_id(jira, issue, resolution_id)
                        new_note.entry = new_note.entry + "\nJira issue set to resolved."
                else:
                    # Re-open finding with notes stating why re-open
                    resolution_id = jira_get_resolution_id(jira, issue,
                                                        "Resolve Issue")
                    if resolution_id is not None:
                        jira_change_resolution_id(jira, issue, resolution_id)
                        new_note.entry = new_note.entry + "\nJira issue re-opened."

            # Update Dojo and Jira with a notes
            add_comment(finding, new_note, force_push=True)
            finding.save()

            messages.add_message(
                request,
                messages.SUCCESS,
                'Defect Reviewed',
                extra_tags='alert-success')
            return HttpResponseRedirect(
                reverse('view_test', args=(finding.test.id, )))

    else:
        form = DefectFindingForm()

    product_tab = Product_Tab(finding.test.engagement.product.id, title="Jira Status Review", tab="findings")

    return render(request, 'dojo/defect_finding_review.html', {
        'finding': finding,
        'product_tab': product_tab,
        'user': request.user,
        'form': form
    })


@user_passes_test(lambda u: u.is_staff)
def reopen_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    finding.active = True
    finding.mitigated = None
    finding.mitigated_by = request.user
    finding.last_reviewed = finding.mitigated
    finding.last_reviewed_by = request.user
    finding.save()

    messages.add_message(
        request,
        messages.SUCCESS,
        'Finding Reopened.',
        extra_tags='alert-success')
    create_notification(event='other',
                        title='Reopening of %s' % finding.title,
                        description='The finding "%s" was reopened by %s' % (finding.title, request.user),
                        url=request.build_absolute_uri(reverse('view_test', args=(finding.test.id, ))),
                        )
    return HttpResponseRedirect(reverse('view_finding', args=(finding.id, )))


@user_passes_test(lambda u: u.is_staff)
def apply_template_cwe(request, fid):
    finding = get_object_or_404(Finding, id=fid)

    form = FindingFormID(instance=finding)

    if request.method == 'POST':
        form = FindingFormID(request.POST, instance=finding)
        if form.is_valid():
            finding = apply_cwe_to_template(finding)
            finding.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Finding CWE template applied successfully.',
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_finding', args=(fid, )))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'Unable to apply CWE template finding, please try again.',
                extra_tags='alert-danger')
    else:
        return HttpResponseForbidden()


def delete_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)

    if request.method == 'POST':
        form = DeleteFindingForm(request.POST, instance=finding)
        if form.is_valid():
            tid = finding.test.id
            product = finding.test.engagement.product
            del finding.tags
            finding.delete()
            calculate_grade(product)
            messages.add_message(
                request,
                messages.SUCCESS,
                'Finding deleted successfully.',
                extra_tags='alert-success')
            create_notification(event='other',
                                title='Deletion of %s' % finding.title,
                                description='The finding "%s" was deleted by %s' % (finding.title, request.user),
                                url=request.build_absolute_uri(reverse('all_findings')),
                                recipients=[finding.test.engagement.lead],
                                icon="exclamation-triangle")
            return HttpResponseRedirect(reverse('view_test', args=(tid, )))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'Unable to delete finding, please try again.',
                extra_tags='alert-danger')
    else:
        return HttpResponseForbidden()


@user_passes_test(lambda u: u.is_staff)
def edit_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    old_status = finding.status()
    form = FindingForm(instance=finding, template=False)
    form.initial['tags'] = [tag.name for tag in finding.tags]
    form_error = False
    jform = None
    try:
        jissue = JIRA_Issue.objects.get(finding=finding)
        enabled = True
    except:
        enabled = False
        pass

    if get_system_setting('enable_jira') and JIRA_PKey.objects.filter(
            product=finding.test.engagement.product) != 0:
        jform = JIRAFindingForm(enabled=enabled, prefix='jiraform')

    if request.method == 'POST':
        form = FindingForm(request.POST, instance=finding, template=False)
        source = request.POST.get("source", "")
        page = request.POST.get("page", "")
        if finding.active:
            if (form['active'].value() is False or form['false_p'].value()) and form['duplicate'].value() is False:
                note_type_activation = Note_Type.objects.filter(is_active=True).count()
                closing_disabled = 0
                if note_type_activation:
                    closing_disabled = len(get_missing_mandatory_notetypes(finding))
                if closing_disabled != 0:
                    error_inactive = ValidationError('Can not set a finding as inactive without adding all mandatory notes',
                                                     code='inactive_without_mandatory_notes')
                    error_false_p = ValidationError('Can not set a finding as false positive without adding all mandatory notes',
                                                    code='false_p_without_mandatory_notes')
                    if form['active'].value() is False:
                        form.add_error('active', error_inactive)
                    if form['false_p'].value():
                        form.add_error('false_p', error_false_p)
                    messages.add_message(request,
                                         messages.ERROR,
                                         'Can not set a finding as inactive or false positive without adding all mandatory notes',
                                         extra_tags='alert-danger')
        if form.is_valid():
            new_finding = form.save(commit=False)
            new_finding.test = finding.test
            new_finding.numerical_severity = Finding.get_numerical_severity(
                new_finding.severity)
            if new_finding.false_p or new_finding.active is False:
                new_finding.mitigated = timezone.now()
                new_finding.mitigated_by = request.user
            if new_finding.active is True:
                new_finding.false_p = False
                new_finding.mitigated = None
                new_finding.mitigated_by = None
            if new_finding.duplicate:
                new_finding.duplicate = True
                new_finding.active = False
                new_finding.verified = False
                parent_find_string = request.POST.get('duplicate_choice', '')
                if parent_find_string:
                    parent_find = Finding.objects.get(id=int(parent_find_string.split(':')[0]))
                    new_finding.duplicate_finding = parent_find
                    parent_find.duplicate_list.add(new_finding)
                    parent_find.found_by.add(new_finding.test.test_type)
            if not new_finding.duplicate and new_finding.duplicate_finding:
                parent_find = new_finding.duplicate_finding
                if parent_find.found_by is not new_finding.found_by:
                    parent_find.duplicate_list.remove(new_finding)
                parent_find.found_by.remove(new_finding.test.test_type)
                new_finding.duplicate_finding = None

            create_template = new_finding.is_template
            # always false now since this will be deprecated soon in favor of new Finding_Template model
            new_finding.is_template = False
            new_finding.endpoints.set(form.cleaned_data['endpoints'])
            new_finding.last_reviewed = timezone.now()
            new_finding.last_reviewed_by = request.user
            tags = request.POST.getlist('tags')
            t = ", ".join('"{0}"'.format(w) for w in tags)
            new_finding.tags = t
            new_finding.save()
            if 'jiraform-push_to_jira' in request.POST:
                jform = JIRAFindingForm(
                    request.POST, prefix='jiraform', enabled=enabled)
                if jform.is_valid():
                    if JIRA_Issue.objects.filter(finding=new_finding).exists():
                        update_issue_task.delay(
                            new_finding, old_status,
                            jform.cleaned_data.get('push_to_jira'))
                    else:
                        add_issue_task.delay(
                            new_finding,
                            jform.cleaned_data.get('push_to_jira'))
            tags = request.POST.getlist('tags')
            t = ", ".join('"{0}"'.format(w) for w in tags)
            new_finding.tags = t

            messages.add_message(
                request,
                messages.SUCCESS,
                'Finding saved successfully.',
                extra_tags='alert-success')
            if create_template:
                templates = Finding_Template.objects.filter(
                    title=new_finding.title)
                if len(templates) > 0:
                    messages.add_message(
                        request,
                        messages.ERROR,
                        'A finding template was not created.  A template with this title already '
                        'exists.',
                        extra_tags='alert-danger')
                else:
                    template = Finding_Template(
                        title=new_finding.title,
                        cwe=new_finding.cwe,
                        severity=new_finding.severity,
                        description=new_finding.description,
                        mitigation=new_finding.mitigation,
                        impact=new_finding.impact,
                        references=new_finding.references,
                        numerical_severity=new_finding.numerical_severity)
                    template.save()
                    messages.add_message(
                        request,
                        messages.SUCCESS,
                        'A finding template was also created.',
                        extra_tags='alert-success')
            page_value = ""
            if page:
                try:
                    if int(page):
                        page_value = "&page=" + str(page)
                except:
                    pass

            if source == "test":
                return HttpResponseRedirect(reverse('view_test', args=(new_finding.test.id, )))
            elif source == "product_findings":
                return HttpResponseRedirect(reverse('product_open_findings', args=(new_finding.test.engagement.product.id, )) + '?test__engagement__product=' + str(new_finding.test.engagement.product.id) + page_value)
            elif source == "all_product_findings":
                return HttpResponseRedirect(reverse('open_findings') + '?' + page_value)
            else:
                return HttpResponseRedirect(reverse('view_finding', args=(new_finding.id, )))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'There appears to be errors on the form, please correct below.',
                extra_tags='alert-danger')
            form_error = True

    if form_error and 'endpoints' in form.cleaned_data:
        form.fields['endpoints'].queryset = form.cleaned_data['endpoints']
    else:
        form.fields['endpoints'].queryset = finding.endpoints.all()
    form.initial['tags'] = [tag.name for tag in finding.tags]

    if finding.test.engagement.deduplication_on_engagement:
        finding_dupes = Finding.objects.all().filter(
            test__engagement=finding.test.engagement).filter(
            title=finding.title).exclude(
            id=finding.id)
    else:
        finding_dupes = Finding.objects.all().filter(
            title=finding.title).exclude(
            id=finding.id)
    product_tab = Product_Tab(finding.test.engagement.product.id, title="Edit Finding", tab="findings")
    return render(request, 'dojo/edit_findings.html', {
        'product_tab': product_tab,
        'form': form,
        'finding': finding,
        'jform': jform,
        'dupes': finding_dupes,
    })


@user_passes_test(lambda u: u.is_staff)
def touch_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    finding.last_reviewed = timezone.now()
    finding.last_reviewed_by = request.user
    finding.save()
    return HttpResponseRedirect(reverse('view_finding', args=(finding.id, )))


@user_passes_test(lambda u: u.is_staff)
def request_finding_review(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    user = get_object_or_404(Dojo_User, id=request.user.id)
    # in order to review a finding, we need to capture why a review is needed
    # we can do this with a Note
    if request.method == 'POST':
        form = ReviewFindingForm(request.POST)

        if form.is_valid():
            now = timezone.now()
            new_note = Notes()
            new_note.entry = "Review Request: " + form.cleaned_data['entry']
            new_note.private = True
            new_note.author = request.user
            new_note.date = now
            new_note.save()
            finding.notes.add(new_note)
            finding.active = False
            finding.verified = False
            finding.under_review = True
            finding.review_requested_by = user
            finding.last_reviewed = now
            finding.last_reviewed_by = request.user

            users = form.cleaned_data['reviewers']
            finding.reviewers.set(users)
            finding.save()
            reviewers = ""
            for suser in form.cleaned_data['reviewers']:
                reviewers += str(suser) + ", "
            reviewers = reviewers[:-2]

            create_notification(event='review_requested',
                                title='Finding review requested',
                                description='User %s has requested that users %s review the finding "%s" for accuracy:\n\n%s' % (user, reviewers, finding.title, new_note),
                                icon='check',
                                url=reverse("view_finding", args=(finding.id,)))

            messages.add_message(
                request,
                messages.SUCCESS,
                'Finding marked for review and reviewers notified.',
                extra_tags='alert-success')
            return HttpResponseRedirect(
                reverse('view_finding', args=(finding.id, )))

    else:
        form = ReviewFindingForm()

    product_tab = Product_Tab(finding.test.engagement.product.id, title="Review Finding", tab="findings")

    return render(request, 'dojo/review_finding.html', {
        'finding': finding,
        'product_tab': product_tab,
        'user': user,
        'form': form
    })


@user_passes_test(lambda u: u.is_staff)
def clear_finding_review(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    user = get_object_or_404(Dojo_User, id=request.user.id)
    # in order to clear a review for a finding, we need to capture why and how it was reviewed
    # we can do this with a Note

    if user == finding.review_requested_by or user in finding.reviewers.all():
        pass
    else:
        return HttpResponseForbidden()

    if request.method == 'POST':
        form = ClearFindingReviewForm(request.POST, instance=finding)

        if form.is_valid():
            now = timezone.now()
            new_note = Notes()
            new_note.entry = "Review Cleared: " + form.cleaned_data['entry']
            new_note.author = request.user
            new_note.date = now
            new_note.save()

            finding = form.save(commit=False)

            finding.under_review = False
            finding.last_reviewed = now
            finding.last_reviewed_by = request.user

            finding.reviewers.set([])
            finding.save()

            finding.notes.add(new_note)

            messages.add_message(
                request,
                messages.SUCCESS,
                'Finding review has been updated successfully.',
                extra_tags='alert-success')
            return HttpResponseRedirect(
                reverse('view_finding', args=(finding.id, )))

    else:
        form = ClearFindingReviewForm(instance=finding)

    product_tab = Product_Tab(finding.test.engagement.product.id, title="Clear Finding Review", tab="findings")

    return render(request, 'dojo/clear_finding_review.html', {
        'finding': finding,
        'product_tab': product_tab,
        'user': user,
        'form': form
    })


@user_passes_test(lambda u: u.is_staff)
def mktemplate(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    templates = Finding_Template.objects.filter(title=finding.title)
    if len(templates) > 0:
        messages.add_message(
            request,
            messages.ERROR,
            'A finding template with that title already exists.',
            extra_tags='alert-danger')
    else:
        template = Finding_Template(
            title=finding.title,
            cwe=finding.cwe,
            cve=finding.cve,
            severity=finding.severity,
            description=finding.description,
            mitigation=finding.mitigation,
            impact=finding.impact,
            references=finding.references,
            numerical_severity=finding.numerical_severity)
        template.save()
        tags = [tag.name for tag in list(finding.tags)]
        t = ", ".join('"{0}"'.format(w) for w in tags)
        template.tags = t
        messages.add_message(
            request,
            messages.SUCCESS,
            mark_safe(
                'Finding template added successfully. You may edit it <a href="%s">here</a>.'
                % reverse('edit_template', args=(template.id, ))),
            extra_tags='alert-success')
    return HttpResponseRedirect(reverse('view_finding', args=(finding.id, )))


@user_passes_test(lambda u: u.is_staff)
def find_template_to_apply(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    test = get_object_or_404(Test, id=finding.test.id)
    templates_by_CVE = Finding_Template.objects.annotate(
                                            cve_len=Length('cve'), order=models.Value(1, models.IntegerField())).filter(
                                                cve=finding.cve, cve_len__gt=0).order_by('-last_used')
    if templates_by_CVE.count() == 0:

        templates_by_last_used = Finding_Template.objects.all().order_by(
                                                '-last_used').annotate(
                                                    cve_len=Length('cve'), order=models.Value(2, models.IntegerField()))
        templates = templates_by_last_used
    else:
        templates_by_last_used = Finding_Template.objects.all().exclude(
                                                cve=finding.cve).order_by(
                                                    '-last_used').annotate(
                                                        cve_len=Length('cve'), order=models.Value(2, models.IntegerField()))
        templates = templates_by_last_used.union(templates_by_CVE).order_by('order', '-last_used')

    templates = TemplateFindingFilter(request.GET, queryset=templates)
    paged_templates = get_page_items(request, templates.qs, 25)

    title_words = [
        word for finding in templates.qs for word in finding.title.split()
        if len(word) > 2
    ]

    title_words = sorted(set(title_words))
    product_tab = Product_Tab(test.engagement.product.id, title="Apply Template to Finding", tab="findings")
    return render(
        request, 'dojo/templates.html', {
            'templates': paged_templates,
            'product_tab': product_tab,
            'filtered': templates,
            'title_words': title_words,
            'tid': test.id,
            'fid': fid,
            'add_from_template': False,
            'apply_template': True,
        })


@user_passes_test(lambda u: u.is_staff)
def choose_finding_template_options(request, tid, fid):
    finding = get_object_or_404(Finding, id=fid)
    template = get_object_or_404(Finding_Template, id=tid)
    data = finding.__dict__
    data['tags'] = [tag.name for tag in template.tags]
    form = ApplyFindingTemplateForm(data=data, template=template)
    product_tab = Product_Tab(finding.test.engagement.product.id, title="Finding Template Options", tab="findings")
    return render(request, 'dojo/apply_finding_template.html', {
        'finding': finding,
        'product_tab': product_tab,
        'template': template,
        'form': form,
        'finding_tags': [tag.name for tag in finding.tags.all()],
    })


@user_passes_test(lambda u: u.is_staff)
def apply_template_to_finding(request, fid, tid):
    finding = get_object_or_404(Finding, id=fid)
    template = get_object_or_404(Finding_Template, id=tid)

    if (request.method == "POST"):
        form = ApplyFindingTemplateForm(data=request.POST)

        if form.is_valid():
            template.last_used = timezone.now()
            template.save()
            finding.title = form.cleaned_data['title']
            finding.cwe = form.cleaned_data['cwe']
            finding.cve = form.cleaned_data['cve']
            finding.severity = form.cleaned_data['severity']
            finding.description = form.cleaned_data['description']
            finding.mitigation = form.cleaned_data['mitigation']
            finding.impact = form.cleaned_data['impact']
            finding.references = form.cleaned_data['references']
            finding.last_reviewed = timezone.now()
            finding.last_reviewed_by = request.user
            tags = request.POST.getlist('tags')
            t = ", ".join('"{0}"'.format(w) for w in tags)
            finding.tags = t
            finding.save()
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'There appears to be errors on the form, please correct below.',
                extra_tags='alert-danger')
            # form_error = True
            product_tab = Product_Tab(finding.test.engagement.product.id, title="Apply Finding Template", tab="findings")
            return render(request, 'dojo/apply_finding_template.html', {
                'finding': finding,
                'product_tab': product_tab,
                'template': template,
                'form': form,
            })

        return HttpResponseRedirect(
            reverse('view_finding', args=(finding.id, )))
    else:
        return HttpResponseRedirect(
            reverse('view_finding', args=(finding.id, )))


@user_passes_test(lambda u: u.is_staff)
def add_stub_finding(request, tid):
    test = get_object_or_404(Test, id=tid)
    form = StubFindingForm()
    if request.method == 'POST':
        form = StubFindingForm(request.POST)
        if form.is_valid():
            stub_finding = form.save(commit=False)
            stub_finding.test = test
            stub_finding.reporter = request.user
            stub_finding.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Stub Finding created successfully.',
                extra_tags='alert-success')
            if request.is_ajax():
                data = {
                    'message': 'Stub Finding created successfully.',
                    'id': stub_finding.id,
                    'severity': 'None',
                    'date': formats.date_format(stub_finding.date,
                                                "DATE_FORMAT")
                }
                return HttpResponse(json.dumps(data))
        else:
            if request.is_ajax():
                data = {
                    'message':
                    'Stub Finding form has error, please revise and try again.',
                }
                return HttpResponse(json.dumps(data))

            messages.add_message(
                request,
                messages.ERROR,
                'Stub Finding form has error, please revise and try again.',
                extra_tags='alert-danger')
    add_breadcrumb(title="Add Stub Finding", top_level=False, request=request)
    return HttpResponseRedirect(reverse('view_test', args=(tid, )))


@user_passes_test(lambda u: u.is_staff)
def delete_stub_finding(request, fid):
    finding = get_object_or_404(Stub_Finding, id=fid)
    form = DeleteStubFindingForm(instance=finding)

    if request.method == 'POST':
        form = DeleteStubFindingForm(request.POST, instance=finding)
        if form.is_valid():
            tid = finding.test.id
            if hasattr(finding, 'tags'):
                del finding.tags
            finding.delete()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Potential Finding deleted successfully.',
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_test', args=(tid, )))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'Unable to delete potential finding, please try again.',
                extra_tags='alert-danger')
    else:
        return HttpResponseForbidden()


@user_passes_test(lambda u: u.is_staff)
def promote_to_finding(request, fid):
    finding = get_object_or_404(Stub_Finding, id=fid)
    test = finding.test
    form_error = False
    jira_available = False

    if get_system_setting('enable_jira') and JIRA_PKey.objects.filter(
            product=test.engagement.product) != 0:
        jform = JIRAFindingForm(
            request.POST,
            prefix='jiraform',
            enabled=JIRA_PKey.objects.get(
                product=test.engagement.product).push_all_issues)
        # jira_available = True
    else:
        jform = None

    product_tab = Product_Tab(finding.test.engagement.product.id, title="Promote Finding", tab="findings")

    form = PromoteFindingForm(
        initial={
            'title': finding.title,
            'product_tab': product_tab,
            'date': finding.date,
            'severity': finding.severity,
            'description': finding.description,
            'test': finding.test,
            'reporter': finding.reporter
        })
    if request.method == 'POST':
        form = PromoteFindingForm(request.POST)
        if form.is_valid():
            new_finding = form.save(commit=False)
            new_finding.test = test
            new_finding.reporter = request.user
            new_finding.numerical_severity = Finding.get_numerical_severity(
                new_finding.severity)

            new_finding.active = True
            new_finding.false_p = False
            new_finding.duplicate = False
            new_finding.mitigated = None
            new_finding.verified = True
            new_finding.out_of_scope = False

            new_finding.save()
            new_finding.endpoints.set(form.cleaned_data['endpoints'])
            new_finding.save()

            finding.delete()
            if 'jiraform' in request.POST:
                jform = JIRAFindingForm(
                    request.POST,
                    prefix='jiraform',
                    enabled=JIRA_PKey.objects.get(
                        product=test.engagement.product).push_all_issues)
                if jform.is_valid():
                    add_issue_task.delay(
                        new_finding, jform.cleaned_data.get('push_to_jira'))

            messages.add_message(
                request,
                messages.SUCCESS,
                'Finding promoted successfully.',
                extra_tags='alert-success')

            return HttpResponseRedirect(reverse('view_test', args=(test.id, )))
        else:
            if 'endpoints' in form.cleaned_data:
                form.fields['endpoints'].queryset = form.cleaned_data[
                    'endpoints']
            else:
                form.fields['endpoints'].queryset = Endpoint.objects.none()
            form_error = True
            messages.add_message(
                request,
                messages.ERROR,
                'The form has errors, please correct them below.',
                extra_tags='alert-danger')

    return render(
        request, 'dojo/promote_to_finding.html', {
            'form': form,
            'product_tab': product_tab,
            'test': test,
            'stub_finding': finding,
            'form_error': form_error,
        })


@user_passes_test(lambda u: u.is_staff)
def templates(request):
    templates = Finding_Template.objects.all().order_by('cwe')
    templates = TemplateFindingFilter(request.GET, queryset=templates)
    paged_templates = get_page_items(request, templates.qs, 25)
    title_words = [
        word for finding in templates.qs for word in finding.title.split()
        if len(word) > 2
    ]

    title_words = sorted(set(title_words))
    add_breadcrumb(title="Template Listing", top_level=True, request=request)
    return render(
        request, 'dojo/templates.html', {
            'templates': paged_templates,
            'filtered': templates,
            'title_words': title_words,
        })


def export_templates_to_json(request):
    leads_as_json = serializers.serialize('json', Finding_Template.objects.all())
    return HttpResponse(leads_as_json, content_type='json')


def apply_cwe_mitigation(apply_to_findings, template, update=True):
    count = 0
    if apply_to_findings and template.template_match and template.cwe is not None:
        # Update active, verified findings with the CWE template
        # If CWE only match only update issues where there isn't a CWE + Title match
        if template.template_match_title:
            count = Finding.objects.filter(active=True, verified=True, cwe=template.cwe, title__icontains=template.title).update(mitigation=template.mitigation, impact=template.impact, references=template.references)
        else:
            finding_templates = Finding_Template.objects.filter(cwe=template.cwe, template_match=True, template_match_title=True)

            finding_ids = None
            result_list = None
            # Exclusion list
            for title_template in finding_templates:
                finding_ids = Finding.objects.filter(active=True, verified=True, cwe=title_template.cwe, title__icontains=title_template.title).values_list('id', flat=True)
                if result_list is None:
                    result_list = finding_ids
                else:
                    result_list = list(chain(result_list, finding_ids))

            # If result_list is None the filter exclude won't work
            if result_list:
                count = Finding.objects.filter(active=True, verified=True, cwe=template.cwe).exclude(id__in=result_list)
            else:
                count = Finding.objects.filter(active=True, verified=True, cwe=template.cwe)

            if update:
                # MySQL won't allow an 'update in statement' so loop will have to do
                for finding in count:
                    finding.mitigation = template.mitigation
                    finding.impact = template.impact
                    finding.references = template.references
                    template.last_used = timezone.now()
                    template.save()
                    new_note = Notes()
                    new_note.entry = 'CWE remediation text applied to finding for CWE: %s using template: %s.' % (template.cwe, template.title)
                    new_note.author, created = User.objects.get_or_create(username='System')
                    new_note.save()
                    finding.notes.add(new_note)
                    finding.save()

            count = count.count()
    return count


@user_passes_test(lambda u: u.is_staff)
def add_template(request):
    form = FindingTemplateForm()
    if request.method == 'POST':
        form = FindingTemplateForm(request.POST)
        if form.is_valid():
            apply_message = ""
            template = form.save(commit=False)
            template.numerical_severity = Finding.get_numerical_severity(template.severity)
            template.save()
            tags = request.POST.getlist('tags')
            t = ", ".join('"{0}"'.format(w) for w in tags)
            template.tags = t
            count = apply_cwe_mitigation(form.cleaned_data["apply_to_findings"], template)
            if count > 0:
                apply_message = " and " + str(count) + pluralize(count, 'finding,findings') + " "

            messages.add_message(
                request,
                messages.SUCCESS,
                'Template created successfully. ' + apply_message,
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('templates'))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'Template form has error, please revise and try again.',
                extra_tags='alert-danger')
    add_breadcrumb(title="Add Template", top_level=False, request=request)
    return render(request, 'dojo/add_template.html', {
        'form': form,
        'name': 'Add Template'
    })


@user_passes_test(lambda u: u.is_staff)
def edit_template(request, tid):
    template = get_object_or_404(Finding_Template, id=tid)
    form = FindingTemplateForm(instance=template)

    apply_message = ""
    if request.method == 'POST':
        form = FindingTemplateForm(request.POST, instance=template)
        if form.is_valid():
            template = form.save(commit=False)
            template.numerical_severity = Finding.get_numerical_severity(template.severity)
            template.save()

            count = apply_cwe_mitigation(form.cleaned_data["apply_to_findings"], template)
            if count > 0:
                apply_message = " and " + str(count) + " " + pluralize(count, 'finding,findings') + " "

            tags = request.POST.getlist('tags')
            t = ", ".join('"{0}"'.format(w) for w in tags)
            template.tags = t
            messages.add_message(
                request,
                messages.SUCCESS,
                'Template ' + apply_message + 'updated successfully.',
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('templates'))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'Template form has error, please revise and try again.',
                extra_tags='alert-danger')
    else:
        count = apply_cwe_mitigation(True, template, False)

    form.initial['tags'] = [tag.name for tag in template.tags]
    add_breadcrumb(title="Edit Template", top_level=False, request=request)
    return render(request, 'dojo/add_template.html', {
        'form': form,
        'count': count,
        'name': 'Edit Template',
        'template': template,
    })


@user_passes_test(lambda u: u.is_staff)
def delete_template(request, tid):
    template = get_object_or_404(Finding_Template, id=tid)

    form = DeleteFindingTemplateForm(instance=template)

    if request.method == 'POST':
        form = DeleteFindingTemplateForm(request.POST, instance=template)
        if form.is_valid():
            del template.tags
            template.delete()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Finding Template deleted successfully.',
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('templates'))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'Unable to delete Template, please revise and try again.',
                extra_tags='alert-danger')
    else:
        return HttpResponseForbidden()


@user_passes_test(lambda u: u.is_staff)
def finding_from_template(request, tid):
    template = get_object_or_404(Finding_Template, id=tid)


@user_passes_test(lambda u: u.is_staff)
def manage_images(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    images_formset = FindingImageFormSet(queryset=finding.images.all())
    error = False

    if request.method == 'POST':
        images_formset = FindingImageFormSet(
            request.POST, request.FILES, queryset=finding.images.all())
        if images_formset.is_valid():
            # remove all from database and disk

            images_formset.save()

            for obj in images_formset.deleted_objects:
                os.remove(os.path.join(settings.MEDIA_ROOT, obj.image.name))
                if obj.image_thumbnail is not None and os.path.isfile(
                        os.path.join(settings.MEDIA_ROOT, obj.image_thumbnail.name)):
                    os.remove(os.path.join(settings.MEDIA_ROOT, obj.image_thumbnail.name))
                if obj.image_medium is not None and os.path.isfile(
                        os.path.join(settings.MEDIA_ROOT, obj.image_medium.name)):
                    os.remove(os.path.join(settings.MEDIA_ROOT, obj.image_medium.name))
                if obj.image_large is not None and os.path.isfile(
                        os.path.join(settings.MEDIA_ROOT, obj.image_large.name)):
                    os.remove(os.path.join(settings.MEDIA_ROOT, obj.image_large.name))

            for obj in images_formset.new_objects:
                finding.images.add(obj)

            orphan_images = FindingImage.objects.filter(finding__isnull=True)
            for obj in orphan_images:
                os.remove(os.path.join(settings.MEDIA_ROOT, obj.image.name))
                if obj.image_thumbnail is not None and os.path.isfile(
                        os.path.join(settings.MEDIA_ROOT, obj.image_thumbnail.name)):
                    os.remove(os.path.join(settings.MEDIA_ROOT, obj.image_thumbnail.name))
                if obj.image_medium is not None and os.path.isfile(
                        os.path.join(settings.MEDIA_ROOT, obj.image_medium.name)):
                    os.remove(os.path.join(settings.MEDIA_ROOT, obj.image_medium.name))
                if obj.image_large is not None and os.path.isfile(
                        os.path.join(settings.MEDIA_ROOT, obj.image_large.name)):
                    os.remove(os.path.join(settings.MEDIA_ROOT, obj.image_large.name))
                obj.delete()

            files = os.listdir(os.path.join(settings.MEDIA_ROOT, 'finding_images'))

            for file in files:
                with_media_root = os.path.join(settings.MEDIA_ROOT, 'finding_images', file)
                with_part_root_only = os.path.join('finding_images', file)
                if os.path.isfile(with_media_root):
                    pic = FindingImage.objects.filter(
                        image=with_part_root_only)

                    if len(pic) == 0:
                        os.remove(with_media_root)
                        cache_to_remove = os.path.join(settings.MEDIA_ROOT, 'CACHE', 'images', 'finding_images',
                            os.path.splitext(file)[0])
                        if os.path.isdir(cache_to_remove):
                            shutil.rmtree(cache_to_remove)
                    else:
                        for p in pic:
                            if p.finding_set is None:
                                p.delete()

            messages.add_message(
                request,
                messages.SUCCESS,
                'Images updated successfully.',
                extra_tags='alert-success')
        else:
            error = True
            messages.add_message(
                request,
                messages.ERROR,
                'Please check form data and try again.',
                extra_tags='alert-danger')

        if not error:
            return HttpResponseRedirect(reverse('view_finding', args=(fid, )))
    product_tab = Product_Tab(finding.test.engagement.product.id, title="Manage Finding Images", tab="findings")
    return render(
        request, 'dojo/manage_images.html', {
            'product_tab': product_tab,
            'images_formset': images_formset,
            'active_tab': 'findings',
            'name': 'Manage Finding Images',
            'finding': finding,
        })


def download_finding_pic(request, token):
    mimetypes.init()

    try:
        access_token = FindingImageAccessToken.objects.get(token=token)
        sizes = {
            'thumbnail': access_token.image.image_thumbnail,
            'small': access_token.image.image_small,
            'medium': access_token.image.image_medium,
            'large': access_token.image.image_large,
            'original': access_token.image.image,
        }
        if access_token.size not in list(sizes.keys()):
            raise Http404
        size = access_token.size
        # we know there is a token - is it for this image
        if access_token.size == size:
            ''' all is good, one time token used, delete it '''
            access_token.delete()
        else:
            raise PermissionDenied
    except:
        raise PermissionDenied

    response = StreamingHttpResponse(FileIterWrapper(open(sizes[size].path, 'rb')))
    response['Content-Disposition'] = 'inline'
    mimetype, encoding = mimetypes.guess_type(sizes[size].name)
    response['Content-Type'] = mimetype
    return response


@user_passes_test(lambda u: u.is_staff)
def merge_finding_product(request, pid):
    product = get_object_or_404(Product, pk=pid)
    finding_to_update = request.GET.getlist('finding_to_update')
    findings = None

    if (request.GET.get('merge_findings') or request.method == 'POST') and finding_to_update:
        finding = Finding.objects.get(id=finding_to_update[0], test__engagement__product=product)
        findings = Finding.objects.filter(id__in=finding_to_update, test__engagement__product=product)
        form = MergeFindings(finding=finding, findings=findings, initial={'finding_to_merge_into': finding_to_update[0]})

        if request.method == 'POST':
            form = MergeFindings(request.POST, finding=finding, findings=findings)
            if form.is_valid():
                finding_to_merge_into = form.cleaned_data['finding_to_merge_into']
                findings_to_merge = form.cleaned_data['findings_to_merge']
                finding_descriptions = ''
                finding_references = ''
                notes_entry = ''
                static = False
                dynamic = False

                if finding_to_merge_into not in findings_to_merge:
                    for finding in findings_to_merge.exclude(pk=finding_to_merge_into.pk):
                        notes_entry = "{} {} ({}),".format(notes_entry, finding.title, finding.id)
                        if finding.static_finding:
                            static = finding.static_finding

                        if finding.dynamic_finding:
                            dynamic = finding.dynamic_finding

                        if finding.line:
                            line = finding.line

                        if finding.file_path:
                            file_path = finding.file_path

                        # If checked merge the descriptions
                        if form.cleaned_data['append_description']:
                            finding_descriptions = "{}\n{}".format(finding_descriptions, finding.description)
                            # Workaround until file path is one to many
                            if finding.file_path:
                                finding_descriptions = "{}\n**File Path:** {}\n".format(finding_descriptions, finding.file_path)

                        # If checked merge the Reference
                        if form.cleaned_data['append_reference']:
                            finding_references = "{}\n{}".format(finding_references, finding.references)

                        # if checked merge the endpoints
                        if form.cleaned_data['add_endpoints']:
                            finding_to_merge_into.endpoints.add(*finding.endpoints.all())

                        # if checked merge the tags
                        if form.cleaned_data['tag_finding']:
                            for tag in finding.tags:
                                Tag.objects.add_tag(finding_to_merge_into, tag)

                        # if checked re-assign the burp requests to the merged finding
                        if form.cleaned_data['dynamic_raw']:
                            BurpRawRequestResponse.objects.filter(finding=finding).update(finding=finding_to_merge_into)

                        # Add merge finding information to the note if set to inactive
                        if form.cleaned_data['finding_action'] == "inactive":
                            single_finding_notes_entry = "Finding has been set to inactive and merged with the finding: {}.".format(finding_to_merge_into.title)
                            note = Notes(entry=single_finding_notes_entry, author=request.user)
                            note.save()
                            finding.notes.add(note)

                            # If the merged finding should be tagged as merged-into
                            if form.cleaned_data['mark_tag_finding']:
                                Tag.objects.add_tag(finding, "merged-inactive")

                    # Update the finding to merge into
                    if finding_descriptions != '':
                        finding_to_merge_into.description = "{}\n\n{}".format(finding_to_merge_into.description, finding_descriptions)

                    if finding_to_merge_into.static_finding:
                        static = finding.static_finding

                    if finding_to_merge_into.dynamic_finding:
                        dynamic = finding.dynamic_finding

                    if finding_to_merge_into.line is None:
                        line = finding_to_merge_into.line

                    if finding_to_merge_into.file_path is None:
                        file_path = finding_to_merge_into.file_path

                    if finding_references != '':
                        finding_to_merge_into.references = "{}\n{}".format(finding_to_merge_into.references, finding_references)

                    finding_to_merge_into.static_finding = static
                    finding_to_merge_into.dynamic_finding = dynamic

                    # Update the timestamp
                    finding_to_merge_into.last_reviewed = timezone.now()
                    finding_to_merge_into.last_reviewed_by = request.user

                    # Save the data to the merged finding
                    finding_to_merge_into.save()

                    # If the finding merged into should be tagged as merged
                    if form.cleaned_data['mark_tag_finding']:
                        Tag.objects.add_tag(finding_to_merge_into, "merged")

                    finding_action = ""
                    # Take action on the findings
                    if form.cleaned_data['finding_action'] == "inactive":
                        finding_action = "inactivated"
                        findings_to_merge.exclude(pk=finding_to_merge_into.pk).update(active=False, last_reviewed=timezone.now(), last_reviewed_by=request.user)
                    elif form.cleaned_data['finding_action'] == "delete":
                        finding_action = "deleted"
                        findings_to_merge.delete()

                    notes_entry = "Finding consists of merged findings from the following findings: {} which have been {}.".format(notes_entry[:-1], finding_action)
                    note = Notes(entry=notes_entry, author=request.user)
                    note.save()
                    finding_to_merge_into.notes.add(note)

                    messages.add_message(
                        request,
                        messages.SUCCESS,
                        'Findings merged',
                        extra_tags='alert-success')
                    return HttpResponseRedirect(
                        reverse('edit_finding', args=(finding_to_merge_into.id, )))
                else:
                    messages.add_message(request,
                                         messages.ERROR,
                                         'Unable to merge findings. Findings to merge contained in finding to merge into.',
                                         extra_tags='alert-danger')
            else:
                messages.add_message(request,
                                     messages.ERROR,
                                     'Unable to merge findings. Required fields were not selected.',
                                     extra_tags='alert-danger')

    product_tab = Product_Tab(finding.test.engagement.product.id, title="Merge Findings", tab="findings")
    custom_breadcrumb = {"Open Findings": reverse('product_open_findings', args=(finding.test.engagement.product.id, )) + '?test__engagement__product=' + str(finding.test.engagement.product.id)}

    return render(request, 'dojo/merge_findings.html', {
        'form': form,
        'name': 'Merge Findings',
        'finding': finding,
        'product_tab': product_tab,
        'title': product_tab.title,
        'custom_breadcrumb': custom_breadcrumb
    })


@user_passes_test(lambda u: u.is_staff)
def finding_bulk_update_all(request, pid=None):
    form = FindingBulkUpdateForm(request.POST)
    if request.method == "POST":
        finding_to_update = request.POST.getlist('finding_to_update')
        if request.POST.get('delete_bulk_findings') and finding_to_update:
            finds = Finding.objects.filter(id__in=finding_to_update)
            product_calc = list(Product.objects.filter(engagement__test__finding__id__in=finding_to_update).distinct())
            finds.delete()
            for prod in product_calc:
                calculate_grade(prod)
        else:
            if form.is_valid() and finding_to_update:
                finding_to_update = request.POST.getlist('finding_to_update')
                finds = Finding.objects.filter(id__in=finding_to_update).order_by("finding__test__engagement__product__id")
                if form.cleaned_data['severity']:
                    finds.update(severity=form.cleaned_data['severity'],
                                 numerical_severity=Finding.get_numerical_severity(form.cleaned_data['severity']),
                                 last_reviewed=timezone.now(),
                                 last_reviewed_by=request.user)
                if form.cleaned_data['status']:
                    finds.update(active=form.cleaned_data['active'],
                                 verified=form.cleaned_data['verified'],
                                 false_p=form.cleaned_data['false_p'],
                                 out_of_scope=form.cleaned_data['out_of_scope'],
                                 is_Mitigated=form.cleaned_data['is_Mitigated'],
                                 last_reviewed=timezone.now(),
                                 last_reviewed_by=request.user)
                if form.cleaned_data['tags']:
                    for finding in finds:
                        tags = request.POST.getlist('tags')
                        ts = ", ".join(tags)
                        finding.tags = ts

                # Update the grade as bulk edits don't go through save
                if form.cleaned_data['severity'] or form.cleaned_data['status']:
                    prev_prod = None
                    for finding in finds:
                        if prev_prod != finding.test.engagement.product.id:
                            calculate_grade(finding.test.engagement.product)
                            prev_prod = finding.test.engagement.product.id

                for finding in finds:
                    from dojo.tools import tool_issue_updater
                    tool_issue_updater.async_tool_issue_update(finding)

                    if JIRA_PKey.objects.filter(product=finding.test.engagement.product).count() == 0:
                        log_jira_alert('Finding cannot be pushed to jira as there is no jira configuration for this product.', finding)
                    else:
                        old_status = finding.status()
                        if form.cleaned_data['push_to_jira']:
                            if JIRA_Issue.objects.filter(finding=finding).exists():
                                update_issue_task.delay(finding, old_status, True)
                            else:
                                add_issue_task.delay(finding, True)

                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Bulk edit of findings was successful.  Check to make sure it is what you intended.',
                                     extra_tags='alert-success')
            else:
                messages.add_message(request,
                                     messages.ERROR,
                                     'Unable to process bulk update. Required fields were not selected.',
                                     extra_tags='alert-danger')

        return HttpResponseRedirect(request.META.get('HTTP_REFERER'))


def find_available_notetypes(notes):
    single_note_types = Note_Type.objects.filter(is_single=True, is_active=True).values_list('id', flat=True)
    multiple_note_types = Note_Type.objects.filter(is_single=False, is_active=True).values_list('id', flat=True)
    available_note_types = []
    for note_type_id in multiple_note_types:
        available_note_types.append(note_type_id)
    for note_type_id in single_note_types:
        for note in notes:
            if note_type_id == note.note_type_id:
                break
        else:
            available_note_types.append(note_type_id)
    queryset = Note_Type.objects.filter(id__in=available_note_types).order_by('-id')
    return queryset


def get_missing_mandatory_notetypes(finding):
    notes = finding.notes.all()
    mandatory_note_types = Note_Type.objects.filter(is_mandatory=True, is_active=True).values_list('id', flat=True)
    notes_to_be_added = []
    for note_type_id in mandatory_note_types:
        for note in notes:
            if note_type_id == note.note_type_id:
                break
        else:
            notes_to_be_added.append(note_type_id)
    queryset = Note_Type.objects.filter(id__in=notes_to_be_added)
    return queryset


@user_passes_test(lambda u: u.is_staff)
@require_POST
def mark_finding_duplicate(request, original_id, duplicate_id):
    original = get_object_or_404(Finding, id=original_id)
    duplicate = get_object_or_404(Finding, id=duplicate_id)

    if original.test.engagement != duplicate.test.engagement:
        if original.test.engagement.deduplication_on_engagement or duplicate.test.engagement.deduplication_on_engagement:
            raise ValueError('Marking finding {} as duplicate of {} failed as they are not in the same engagement and deduplication_on_engagement is enabled for at least one of them')

    duplicate.duplicate = True
    duplicate.active = False
    duplicate.verified = False
    duplicate.duplicate_finding = original
    duplicate.last_reviewed = timezone.now()
    duplicate.last_reviewed_by = request.user
    duplicate.save()
    original.duplicate_list.add(duplicate)
    original.found_by.add(duplicate.test.test_type)
    original.save()
    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))


@user_passes_test(lambda u: u.is_staff)
@require_POST
def reset_finding_duplicate_status(request, duplicate_id):
    duplicate = get_object_or_404(Finding, id=duplicate_id)
    duplicate.duplicate = False
    duplicate.active = True
    if duplicate.duplicate_finding:
        duplicate.duplicate_finding.duplicate_list.remove(duplicate)
        duplicate.duplicate_finding = None
    duplicate.last_reviewed = timezone.now()
    duplicate.last_reviewed_by = request.user
    duplicate.save()
    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))
