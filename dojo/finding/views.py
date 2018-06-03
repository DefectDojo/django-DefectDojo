# #  findings
import base64
import json
import logging
import mimetypes
import os
import shutil

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.http import Http404, HttpResponse
from django.http import HttpResponseRedirect, HttpResponseForbidden
from django.http import StreamingHttpResponse
from django.shortcuts import render, get_object_or_404
from django.utils import formats
from django.utils.safestring import mark_safe
from django.utils import timezone

from dojo.filters import OpenFindingFilter, \
    OpenFingingSuperFilter, AcceptedFingingSuperFilter, \
    ClosedFingingSuperFilter, TemplateFindingFilter
from dojo.forms import NoteForm, CloseFindingForm, FindingForm, PromoteFindingForm, FindingTemplateForm, \
    DeleteFindingTemplateForm, FindingImageFormSet, JIRAFindingForm, ReviewFindingForm, ClearFindingReviewForm, \
    DefectFindingForm, StubFindingForm, DeleteFindingForm, DeleteStubFindingForm, ApplyFindingTemplateForm, FindingBulkUpdateForm
from dojo.models import Product_Type, Finding, Notes, \
    Risk_Acceptance, BurpRawRequestResponse, Stub_Finding, Endpoint, Finding_Template, FindingImage, \
    FindingImageAccessToken, JIRA_Issue, JIRA_PKey, Dojo_User, Cred_Mapping, Test, System_Settings
from dojo.utils import get_page_items, add_breadcrumb, FileIterWrapper, process_notifications, \
    add_comment, jira_get_resolution_id, jira_change_resolution_id, get_jira_connection, \
    get_system_setting, create_notification, tab_view_count

from dojo.tasks import add_issue_task, update_issue_task, add_comment_task

logger = logging.getLogger(__name__)
"""
Greg
Status: in prod
on the nav menu open findings returns all the open findings for a given
engineer
"""


def open_findings(request, pid=None):
    show_product_column = True
    findings = Finding.objects.filter(
        mitigated__isnull=True,
        verified=True,
        false_p=False,
        duplicate=False,
        out_of_scope=False)

    if request.user.is_staff:
        findings = OpenFingingSuperFilter(
            request.GET, queryset=findings, user=request.user)
    else:
        findings = findings.filter(
            test__engagement__product__authorized_users__in=[request.user])
        findings = OpenFindingFilter(
            request.GET, queryset=findings, user=request.user)

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

    add_breadcrumb(
        title="Open findings", top_level=not len(request.GET), request=request)

    found_by = None
    try:
        found_by = findings.found_by.all().distinct()
    except:
        found_by = None
        pass

    # Only show product tab view in product
    tab_product = None
    tab_engagements = None
    tab_findings = None
    tab_endpoints = None
    tab_benchmarks = None
    active_tab = None
    if pid:
        active_tab = "findings"
        show_product_column = False
        tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(pid)

    system_settings = System_Settings.objects.get()
    return render(
        request, 'dojo/open_findings.html', {
            'show_product_column': show_product_column,
            'tab_product': tab_product,
            'tab_engagements': tab_engagements,
            'tab_findings': tab_findings,
            'tab_endpoints': tab_endpoints,
            'tab_benchmarks': tab_benchmarks,
            'active_tab': active_tab,
            "findings": paged_findings,
            "filtered": findings,
            "title_words": title_words,
            'found_by': found_by,
            'system_settings': system_settings
        })


"""
Greg, Jay
Status: in prod
on the nav menu accpted findings returns all the accepted findings for a given
engineer
"""


@user_passes_test(lambda u: u.is_staff)
def accepted_findings(request):
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

    add_breadcrumb(
        title="Accepted findings",
        top_level=not len(request.GET),
        request=request)

    return render(
        request, 'dojo/accepted_findings.html', {
            "findings": paged_findings,
            "filtered": findings,
            "title_words": title_words,
        })


@user_passes_test(lambda u: u.is_staff)
def closed_findings(request):
    findings = Finding.objects.filter(mitigated__isnull=False)
    findings = ClosedFingingSuperFilter(request.GET, queryset=findings)
    title_words = [
        word for finding in findings.qs for word in finding.title.split()
        if len(word) > 2
    ]

    title_words = sorted(set(title_words))
    paged_findings = get_page_items(request, findings.qs, 25)
    add_breadcrumb(
        title="Closed findings",
        top_level=not len(request.GET),
        request=request)
    return render(
        request, 'dojo/closed_findings.html', {
            "findings": paged_findings,
            "filtered": findings,
            "title_words": title_words,
        })


def view_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    cred_finding = Cred_Mapping.objects.filter(
        finding=finding.id).select_related('cred_id').order_by('cred_id')
    creds = Cred_Mapping.objects.filter(
        test=finding.test.id).select_related('cred_id').order_by('cred_id')
    cred_engagement = Cred_Mapping.objects.filter(
        engagement=finding.test.engagement.id).select_related(
            'cred_id').order_by('cred_id')
    user = request.user
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

    if request.method == 'POST':
        form = NoteForm(request.POST)
        if form.is_valid():
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = timezone.now()
            new_note.save()
            finding.notes.add(new_note)
            finding.last_reviewed = new_note.date
            finding.last_reviewed_by = user
            finding.save()
            if jissue is not None:
                add_comment_task(finding, new_note)
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

    add_breadcrumb(parent=finding, top_level=False, request=request)
    system_settings = System_Settings.objects.get()
    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(finding.test.engagement.product.id)

    return render(
        request, 'dojo/view_finding.html', {
            'tab_product': tab_product,
            'tab_engagements': tab_engagements,
            'tab_findings': tab_findings,
            'tab_endpoints': tab_endpoints,
            'tab_benchmarks': tab_benchmarks,
            'active_tab': 'findings',
            'system_settings': system_settings,
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
            'found_by': finding.found_by.all().distinct()
        })


@user_passes_test(lambda u: u.is_staff)
def close_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    # in order to close a finding, we need to capture why it was closed
    # we can do this with a Note
    if request.method == 'POST':
        form = CloseFindingForm(request.POST)

        if form.is_valid():
            now = timezone.now()
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = now
            new_note.save()
            finding.notes.add(new_note)
            finding.active = False
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
            return HttpResponseRedirect(
                reverse('view_test', args=(finding.test.id, )))

    else:
        form = CloseFindingForm()

    add_breadcrumb(
        parent=finding, title="Close", top_level=False, request=request)

    system_settings = System_Settings.objects.get()
    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(finding.test.engagement.product.id)
    return render(request, 'dojo/close_finding.html', {
        'finding': finding,
        'tab_product': tab_product,
        'tab_engagements': tab_engagements,
        'tab_findings': tab_findings,
        'tab_endpoints': tab_endpoints,
        'tab_benchmarks': tab_benchmarks,
        'active_tab': 'findings',
        'user': request.user,
        'form': form
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
                j_issue = JIRA_Issue.objects.get(finding=finding)
                issue = jira.issue(j_issue.jira_id)
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
                jira = get_jira_connection(finding)
                j_issue = JIRA_Issue.objects.get(finding=finding)
                issue = jira.issue(j_issue.jira_id)
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

    add_breadcrumb(
        parent=finding,
        title="Jira Status Review",
        top_level=False,
        request=request)
    system_settings = System_Settings.objects.get()
    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(finding.test.engagement.product.id)
    return render(request, 'dojo/defect_finding_review.html', {
        'finding': finding,
        'tab_product': tab_product,
        'tab_engagements': tab_engagements,
        'tab_findings': tab_findings,
        'tab_endpoints': tab_endpoints,
        'tab_benchmarks': tab_benchmarks,
        'active_tab': 'findings',
        'system_settings': system_settings,
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
        'Finding closed.',
        extra_tags='alert-success')
    return HttpResponseRedirect(reverse('view_finding', args=(finding.id, )))


@user_passes_test(lambda u: u.is_staff)
def delete_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)

    form = DeleteFindingForm(instance=finding)

    if request.method == 'POST':
        form = DeleteFindingForm(request.POST, instance=finding)
        if form.is_valid():
            tid = finding.test.id
            del finding.tags
            finding.delete()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Finding deleted successfully.',
                extra_tags='alert-success')
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
    form = FindingForm(instance=finding)
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
        form = FindingForm(request.POST, instance=finding)
        source = request.POST.get("source", "")
        page = request.POST.get("page", "")

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

            create_template = new_finding.is_template
            # always false now since this will be deprecated soon in favor of new Finding_Template model
            new_finding.is_template = False
            new_finding.endpoints = form.cleaned_data['endpoints']
            new_finding.last_reviewed = timezone.now()
            new_finding.last_reviewed_by = request.user
            tags = request.POST.getlist('tags')
            t = ", ".join(tags)
            new_finding.tags = t
            new_finding.save()
            if 'jiraform-push_to_jira' in request.POST:
                jform = JIRAFindingForm(
                    request.POST, prefix='jiraform', enabled=enabled)
                if jform.is_valid():
                    try:
                        # jissue = JIRA_Issue.objects.get(finding=new_finding)
                        update_issue_task.delay(
                            new_finding, old_status,
                            jform.cleaned_data.get('push_to_jira'))
                    except:
                        add_issue_task.delay(
                            new_finding,
                            jform.cleaned_data.get('push_to_jira'))
                        pass
            tags = request.POST.getlist('tags')
            t = ", ".join(tags)
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
    add_breadcrumb(
        parent=finding, title="Edit", top_level=False, request=request)

    system_settings = System_Settings.objects.get()
    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(finding.test.engagement.product.id)
    return render(request, 'dojo/edit_findings.html', {
        'tab_product': tab_product,
        'tab_engagements': tab_engagements,
        'tab_findings': tab_findings,
        'tab_endpoints': tab_endpoints,
        'tab_benchmarks': tab_benchmarks,
        'active_tab': 'findings',
        'system_settings': system_settings,
        'form': form,
        'finding': finding,
        'jform': jform
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
            finding.reviewers = users
            finding.save()

            create_notification(event='review_requested',
                                title='Finding review requested',
                                description='User %s has requested that you please review the finding "%s" for accuracy:\n\n%s' % (user, finding.title, new_note),
                                icon='check',
                                url=request.build_absolute_uri(reverse("view_finding", args=(finding.id,))))

            messages.add_message(
                request,
                messages.SUCCESS,
                'Finding marked for review and reviewers notified.',
                extra_tags='alert-success')
            return HttpResponseRedirect(
                reverse('view_finding', args=(finding.id, )))

    else:
        form = ReviewFindingForm()

    system_settings = System_Settings.objects.get()
    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(finding.test.engagement.product.id)
    add_breadcrumb(
        parent=finding,
        title="Review Finding",
        top_level=False,
        request=request)
    return render(request, 'dojo/review_finding.html', {
        'finding': finding,
        'tab_product': tab_product,
        'tab_engagements': tab_engagements,
        'tab_findings': tab_findings,
        'tab_endpoints': tab_endpoints,
        'tab_benchmarks': tab_benchmarks,
        'active_tab': 'findings',
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

            finding.reviewers = []
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

    add_breadcrumb(
        parent=finding,
        title="Clear Finding Review",
        top_level=False,
        request=request)
    return render(request, 'dojo/clear_finding_review.html', {
        'finding': finding,
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
            severity=finding.severity,
            description=finding.description,
            mitigation=finding.mitigation,
            impact=finding.impact,
            references=finding.references,
            numerical_severity=finding.numerical_severity)
        template.save()
        template.tags = finding.tags
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
    templates = Finding_Template.objects.all()
    templates = TemplateFindingFilter(request.GET, queryset=templates)
    paged_templates = get_page_items(request, templates.qs, 25)

    title_words = [
        word for finding in templates.qs for word in finding.title.split()
        if len(word) > 2
    ]

    title_words = sorted(set(title_words))
    add_breadcrumb(
        parent=test,
        title="Apply Template to Finding",
        top_level=False,
        request=request)
    return render(
        request, 'dojo/templates.html', {
            'templates': paged_templates,
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
    form = ApplyFindingTemplateForm(data=finding.__dict__, template=template)

    return render(request, 'dojo/apply_finding_template.html', {
        'finding': finding,
        'template': template,
        'form': form,
    })


@user_passes_test(lambda u: u.is_staff)
def apply_template_to_finding(request, fid, tid):
    finding = get_object_or_404(Finding, id=fid)
    template = get_object_or_404(Finding_Template, id=tid)

    if (request.method == "POST"):
        form = ApplyFindingTemplateForm(data=request.POST)

        if form.is_valid():
            finding.title = form.cleaned_data['title']
            finding.cwe = form.cleaned_data['cwe']
            finding.severity = form.cleaned_data['severity']
            finding.description = form.cleaned_data['description']
            finding.mitigation = form.cleaned_data['mitigation']
            finding.impact = form.cleaned_data['impact']
            finding.references = form.cleaned_data['references']
            finding.last_reviewed = timezone.now()
            finding.last_reviewed_by = request.user

            finding.save()
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'There appears to be errors on the form, please correct below.',
                extra_tags='alert-danger')
            # form_error = True

            return render(request, 'dojo/apply_finding_template.html', {
                'finding': finding,
                'template': template,
                'form': form,
            })

        return HttpResponseRedirect(
            reverse('view_finding', args=(finding.id, )))
    else:
        return HttpResponseRedirect(
            reverse('view_finding', args=(finding.id, )))


@user_passes_test(lambda u: u.is_staff)
def delete_finding_note(request, tid, nid):
    note = get_object_or_404(Notes, id=nid)
    if note.author == request.user:
        finding = get_object_or_404(Finding, id=tid)
        finding.notes.remove(note)
        note.delete()
        messages.add_message(
            request,
            messages.SUCCESS,
            'Note removed.',
            extra_tags='alert-success')
        return view_finding(request, tid)
    return HttpResponseForbidden()


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

    form = PromoteFindingForm(
        initial={
            'title': finding.title,
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
            new_finding.endpoints = form.cleaned_data['endpoints']
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
    add_breadcrumb(
        parent=test, title="Promote Finding", top_level=False, request=request)
    return render(
        request, 'dojo/promote_to_finding.html', {
            'form': form,
            'test': test,
            'stub_finding': finding,
            'form_error': form_error,
        })


@user_passes_test(lambda u: u.is_staff)
def templates(request):
    templates = Finding_Template.objects.all()
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


@user_passes_test(lambda u: u.is_staff)
def add_template(request):
    form = FindingTemplateForm()
    if request.method == 'POST':
        form = FindingTemplateForm(request.POST)
        if form.is_valid():
            template = form.save(commit=False)
            template.numerical_severity = Finding.get_numerical_severity(
                template.severity)
            template.save()
            tags = request.POST.getlist('tags')
            t = ", ".join(tags)
            template.tags = t
            messages.add_message(
                request,
                messages.SUCCESS,
                'Template created successfully.',
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
    if request.method == 'POST':
        form = FindingTemplateForm(request.POST, instance=template)
        if form.is_valid():
            template = form.save(commit=False)
            template.numerical_severity = Finding.get_numerical_severity(
                template.severity)
            template.save()
            tags = request.POST.getlist('tags')
            t = ", ".join(tags)
            template.tags = t
            messages.add_message(
                request,
                messages.SUCCESS,
                'Template updated successfully.',
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('templates'))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'Template form has error, please revise and try again.',
                extra_tags='alert-danger')
    form.initial['tags'] = [tag.name for tag in template.tags]
    add_breadcrumb(title="Edit Template", top_level=False, request=request)
    return render(request, 'dojo/add_template.html', {
        'form': form,
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
                os.remove(settings.MEDIA_ROOT + obj.image.name)
                if obj.image_thumbnail is not None and os.path.isfile(
                        settings.MEDIA_ROOT + obj.image_thumbnail.name):
                    os.remove(settings.MEDIA_ROOT + obj.image_thumbnail.name)
                if obj.image_medium is not None and os.path.isfile(
                        settings.MEDIA_ROOT + obj.image_medium.name):
                    os.remove(settings.MEDIA_ROOT + obj.image_medium.name)
                if obj.image_large is not None and os.path.isfile(
                        settings.MEDIA_ROOT + obj.image_large.name):
                    os.remove(settings.MEDIA_ROOT + obj.image_large.name)

            for obj in images_formset.new_objects:
                finding.images.add(obj)

            orphan_images = FindingImage.objects.filter(finding__isnull=True)
            for obj in orphan_images:
                os.remove(settings.MEDIA_ROOT + obj.image.name)
                if obj.image_thumbnail is not None and os.path.isfile(
                        settings.MEDIA_ROOT + obj.image_thumbnail.name):
                    os.remove(settings.MEDIA_ROOT + obj.image_thumbnail.name)
                if obj.image_medium is not None and os.path.isfile(
                        settings.MEDIA_ROOT + obj.image_medium.name):
                    os.remove(settings.MEDIA_ROOT + obj.image_medium.name)
                if obj.image_large is not None and os.path.isfile(
                        settings.MEDIA_ROOT + obj.image_large.name):
                    os.remove(settings.MEDIA_ROOT + obj.image_large.name)
                obj.delete()

            files = os.listdir(settings.MEDIA_ROOT + 'finding_images')

            for file in files:
                with_media_root = settings.MEDIA_ROOT + 'finding_images/' + file
                with_part_root_only = 'finding_images/' + file
                if os.path.isfile(with_media_root):
                    pic = FindingImage.objects.filter(
                        image=with_part_root_only)

                    if len(pic) == 0:
                        os.remove(with_media_root)
                        cache_to_remove = settings.MEDIA_ROOT + '/CACHE/images/finding_images/' + \
                                          os.path.splitext(file)[0]
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
    system_settings = System_Settings.objects.get()
    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(finding.test.engagement.product.id)
    return render(
        request, 'dojo/manage_images.html', {
            'tab_product': tab_product,
            'tab_engagements': tab_engagements,
            'tab_findings': tab_findings,
            'tab_endpoints': tab_endpoints,
            'tab_benchmarks': tab_benchmarks,
            'active_tab': 'findings',
            'system_settings': system_settings,
            'images_formset': images_formset,
            'tab_product': tab_product,
            'tab_engagements': tab_engagements,
            'tab_findings': tab_findings,
            'tab_endpoints': tab_endpoints,
            'tab_benchmarks': tab_benchmarks,
            'active_tab': 'findings',
            'system_settings': system_settings,
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
        if access_token.size not in sizes.keys():
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

    response = StreamingHttpResponse(FileIterWrapper(open(sizes[size].path)))
    response['Content-Disposition'] = 'inline'
    mimetype, encoding = mimetypes.guess_type(sizes[size].name)
    response['Content-Type'] = mimetype
    return response


@user_passes_test(lambda u: u.is_staff)
def finding_bulk_update_all(request, pid=None):
    form = FindingBulkUpdateForm(request.POST)
    if request.method == "POST":
        finding_to_update = request.POST.getlist('finding_to_update')
        if request.POST.get('delete_bulk_findings') and finding_to_update:
            finds = Finding.objects.filter(id__in=finding_to_update)
            finds.delete()
        else:
            if form.is_valid() and finding_to_update:
                finding_to_update = request.POST.getlist('finding_to_update')
                finds = Finding.objects.filter(id__in=finding_to_update)
                if form.cleaned_data['severity']:
                    finds.update(severity=form.cleaned_data['severity'],
                                 numerical_severity=Finding.get_numerical_severity(form.cleaned_data['severity']),
                                 active=form.cleaned_data['active'],
                                 verified=form.cleaned_data['verified'],
                                 false_p=form.cleaned_data['false_p'],
                                 duplicate=form.cleaned_data['duplicate'],
                                 out_of_scope=form.cleaned_data['out_of_scope'])
                else:
                    finds.update(active=form.cleaned_data['active'],
                                 verified=form.cleaned_data['verified'],
                                 false_p=form.cleaned_data['false_p'],
                                 duplicate=form.cleaned_data['duplicate'],
                                 out_of_scope=form.cleaned_data['out_of_scope'])

                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Bulk edit of findings was successful.  Check to make sure it is what you intended.',
                                     extra_tags='alert-success')
            else:
                messages.add_message(request,
                                     messages.ERROR,
                                     'Unable to process bulk update. Required fields were not selected.',
                                     extra_tags='alert-danger')
    if pid:
        return HttpResponseRedirect(reverse('product_open_findings', args=(pid)) + '?test__engagement__product=' + pid)
    else:
        return HttpResponseRedirect(reverse('open_findings', args=()))
