# #  findings
import base64
import logging
from datetime import datetime
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect, HttpResponseForbidden
from django.shortcuts import render, get_object_or_404
from pytz import timezone
from dojo.filters import OpenFindingFilter, \
    OpenFingingSuperFilter, AcceptedFingingSuperFilter, \
    ClosedFingingSuperFilter, TemplateFindingFilter
from dojo.forms import NoteForm, CloseFindingForm, FindingForm, PromoteFindingForm, FindingTemplateForm, \
    DeleteFindingTemplateForm
from dojo.models import Product_Type, Finding, Notes, \
    Risk_Acceptance, BurpRawRequestResponse, Stub_Finding, Endpoint, Finding_Template
from dojo.utils import get_page_items, add_breadcrumb
from django.utils.safestring import mark_safe

localtz = timezone(settings.TIME_ZONE)

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
    datefmt='%d/%b/%Y %H:%M:%S',
    filename=settings.DOJO_ROOT + '/../django_app.log',
)
logger = logging.getLogger(__name__)

"""
Greg
Status: in prod
on the nav menu open findings returns all the open findings for a given
engineer
"""


def open_findings(request):
    findings = Finding.objects.filter(mitigated__isnull=True,
                                      verified=True,
                                      false_p=False,
                                      duplicate=False,
                                      out_of_scope=False)
    if request.user.is_staff:
        findings = OpenFingingSuperFilter(request.GET, queryset=findings, user=request.user)
    else:
        findings = findings.filter(test__engagement__product__authorized_users__in=[request.user])
        findings = OpenFindingFilter(request.GET, queryset=findings, user=request.user)

    title_words = [word
                   for finding in findings
                   for word in finding.title.split() if len(word) > 2]

    title_words = sorted(set(title_words))
    paged_findings = get_page_items(request, findings, 25)

    product_type = None
    if 'test__engagement__product__prod_type' in request.GET:
        p = request.GET.getlist('test__engagement__product__prod_type', [])
        if len(p) == 1:
            product_type = get_object_or_404(Product_Type, id=p[0])

    add_breadcrumb(title="Open findings", top_level=not len(request.GET), request=request)

    return render(request,
                  'dojo/open_findings.html',
                  {"findings": paged_findings,
                   "filtered": findings,
                   "title_words": title_words,
                   })


"""
Greg, Jay
Status: in prod
on the nav menu accpted findings returns all the accepted findings for a given
engineer
"""


@user_passes_test(lambda u: u.is_staff)
def accepted_findings(request):
    user = request.user

    fids = [finding.id for ra in
            Risk_Acceptance.objects.all()
            for finding in ra.accepted_findings.all()]
    findings = Finding.objects.filter(id__in=fids)
    findings = AcceptedFingingSuperFilter(request.GET, queryset=findings)
    title_words = [word for ra in
                   Risk_Acceptance.objects.all()
                   for finding in ra.accepted_findings.order_by(
            'title').values('title').distinct()
                   for word in finding['title'].split() if len(word) > 2]

    title_words = sorted(set(title_words))
    paged_findings = get_page_items(request, findings, 25)

    add_breadcrumb(title="Accepted findings", top_level=not len(request.GET), request=request)

    return render(request,
                  'dojo/accepted_findings.html',
                  {"findings": paged_findings,
                   "filtered": findings,
                   "title_words": title_words,
                   })


@user_passes_test(lambda u: u.is_staff)
def closed_findings(request):
    findings = Finding.objects.filter(mitigated__isnull=False)
    findings = ClosedFingingSuperFilter(request.GET, queryset=findings)
    title_words = [word
                   for finding in findings
                   for word in finding.title.split() if len(word) > 2]

    title_words = sorted(set(title_words))
    paged_findings = get_page_items(request, findings, 25)
    add_breadcrumb(title="Closed findings", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/closed_findings.html',
                  {"findings": paged_findings,
                   "filtered": findings,
                   "title_words": title_words,
                   })


def view_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    user = request.user
    if user.is_staff or user in finding.test.engagement.product.authorized_users.all():
        pass  # user is authorized for this product
    else:
        raise PermissionDenied

    notes = finding.notes.all()

    if request.method == 'POST':
        form = NoteForm(request.POST)
        if form.is_valid():
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = datetime.now(tz=localtz)
            new_note.save()
            finding.notes.add(new_note)
            finding.last_reviewed = new_note.date
            finding.last_reviewed_by = user
            finding.save()
            form = NoteForm()
            messages.add_message(request,
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
    return render(request, 'dojo/view_finding.html',
                  {'finding': finding,
                   'burp_request': burp_request,
                   'burp_response': burp_response,
                   'user': user, 'notes': notes, 'form': form})


@user_passes_test(lambda u: u.is_staff)
def close_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    # in order to close a finding, we need to capture why it was closed
    # we can do this with a Note
    if request.method == 'POST':
        form = CloseFindingForm(request.POST)

        if form.is_valid():
            now = datetime.now(tz=localtz)
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

            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Finding closed.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_test', args=(finding.test.id,)))

    else:
        form = CloseFindingForm()

    add_breadcrumb(parent=finding, title="Close", top_level=False, request=request)
    return render(request, 'dojo/close_finding.html',
                  {'finding': finding,
                   'user': request.user, 'form': form})


@user_passes_test(lambda u: u.is_staff)
def reopen_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    finding.active = True
    finding.mitigated = None
    finding.mitigated_by = request.user
    finding.last_reviewed = finding.mitigated
    finding.last_reviewed_by = request.user
    finding.save()

    messages.add_message(request,
                         messages.SUCCESS,
                         'Finding closed.',
                         extra_tags='alert-success')
    return HttpResponseRedirect(reverse('view_finding', args=(finding.id,)))


@user_passes_test(lambda u: u.is_staff)
def delete_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    tid = finding.test.id
    finding.delete()
    messages.add_message(request,
                         messages.SUCCESS,
                         'Finding deleted successfully.',
                         extra_tags='alert-success')
    return HttpResponseRedirect(reverse('view_test', args=(tid,)))


@user_passes_test(lambda u: u.is_staff)
def edit_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    form = FindingForm(instance=finding)
    form_error = False
    if request.method == 'POST':
        form = FindingForm(request.POST, instance=finding)
        if form.is_valid():
            new_finding = form.save(commit=False)
            new_finding.test = finding.test
            new_finding.numerical_severity = Finding.get_numerical_severity(
                new_finding.severity)
            if new_finding.false_p or new_finding.active is False:
                new_finding.mitigated = datetime.now(tz=localtz)
                new_finding.mitigated_by = request.user
            if new_finding.active is True:
                new_finding.false_p = False
                new_finding.mitigated = None
                new_finding.mitigated_by = None

            create_template = new_finding.is_template
            # always false now since this will be deprecated soon in favor of new Finding_Template model
            new_finding.is_template = False
            new_finding.endpoints = form.cleaned_data['endpoints']
            new_finding.last_reviewed = datetime.now(tz=localtz)
            new_finding.last_reviewed_by = request.user
            new_finding.save()

            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Finding saved successfully.',
                                 extra_tags='alert-success')
            if create_template:
                templates = Finding_Template.objects.filter(title=new_finding.title)
                if len(templates) > 0:
                    messages.add_message(request,
                                         messages.ERROR,
                                         'A finding template was not created.  A template with this title already '
                                         'exists.',
                                         extra_tags='alert-danger')
                else:
                    template = Finding_Template(title=new_finding.title,
                                                cwe=new_finding.cwe,
                                                severity=new_finding.severity,
                                                description=new_finding.description,
                                                mitigation=new_finding.mitigation,
                                                impact=new_finding.impact,
                                                references=new_finding.references,
                                                numerical_severity=new_finding.numerical_severity)
                    template.save()
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         'A finding template was also created.',
                                         extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_finding', args=(new_finding.id,)))
        else:
            messages.add_message(request,
                                 messages.ERROR,
                                 'There appears to be errors on the form, please correct below.',
                                 extra_tags='alert-danger')
            form_error = True

    if form_error and 'endpoints' in form.cleaned_data:
        form.fields['endpoints'].queryset = form.cleaned_data['endpoints']
    else:
        form.fields['endpoints'].queryset = finding.endpoints.all()

    add_breadcrumb(parent=finding, title="Edit", top_level=False, request=request)
    return render(request, 'dojo/edit_findings.html',
                  {'form': form,
                   'finding': finding,
                   })


@user_passes_test(lambda u: u.is_staff)
def touch_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    finding.last_reviewed = datetime.now(tz=localtz)
    finding.last_reviewed_by = request.user
    finding.save()
    return HttpResponseRedirect(reverse('view_finding', args=(finding.id,)))


@user_passes_test(lambda u: u.is_staff)
def mktemplate(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    templates = Finding_Template.objects.filter(title=finding.title)
    if len(templates) > 0:
        messages.add_message(request,
                             messages.ERROR,
                             'A finding with that title already exists.',
                             extra_tags='alert-danger')
    else:
        template = Finding_Template(title=finding.title,
                                    cwe=finding.cwe,
                                    severity=finding.severity,
                                    description=finding.description,
                                    mitigation=finding.mitigation,
                                    impact=finding.impact,
                                    references=finding.references,
                                    numerical_severity=finding.numerical_severity)
        template.save()
        messages.add_message(request,
                             messages.SUCCESS,
                             mark_safe('Finding template added successfully. You may edit it <a href="%s">here</a>.' %
                                       reverse('edit_template',
                                               args=(template.id,))),
                             extra_tags='alert-success')
    return HttpResponseRedirect(reverse('view_finding', args=(finding.id,)))


@user_passes_test(lambda u: u.is_staff)
def delete_finding_note(request, tid, nid):
    note = get_object_or_404(Notes, id=nid)
    if note.author == request.user:
        finding = get_object_or_404(Finding, id=tid)
        finding.notes.remove(note)
        note.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             'Note removed.',
                             extra_tags='alert-success')
        return view_finding(request, tid)
    return HttpResponseForbidden()


@user_passes_test(lambda u: u.is_staff)
def delete_stub_finding(request, fid):
    finding = get_object_or_404(Stub_Finding, id=fid)
    tid = finding.test.id
    finding.delete()
    messages.add_message(request,
                         messages.SUCCESS,
                         'Potential Finding deleted successfully.',
                         extra_tags='alert-success')
    return HttpResponseRedirect(reverse('view_test', args=(tid,)))


@user_passes_test(lambda u: u.is_staff)
def promote_to_finding(request, fid):
    finding = get_object_or_404(Stub_Finding, id=fid)
    test = finding.test
    form_error = False
    form = PromoteFindingForm(initial={'title': finding.title,
                                       'date': finding.date,
                                       'severity': finding.severity,
                                       'description': finding.description,
                                       'test': finding.test,
                                       'reporter': finding.reporter})
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

            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Finding promoted successfully.',
                                 extra_tags='alert-success')

            return HttpResponseRedirect(reverse('view_test', args=(test.id,)))
        else:
            if 'endpoints' in form.cleaned_data:
                form.fields['endpoints'].queryset = form.cleaned_data['endpoints']
            else:
                form.fields['endpoints'].queryset = Endpoint.objects.none()
            form_error = True
            messages.add_message(request,
                                 messages.ERROR,
                                 'The form has errors, please correct them below.',
                                 extra_tags='alert-danger')
    add_breadcrumb(parent=test, title="Promote Finding", top_level=False, request=request)
    return render(request, 'dojo/promote_to_finding.html',
                  {'form': form,
                   'test': test,
                   'stub_finding': finding,
                   'form_error': form_error,
                   })


@user_passes_test(lambda u: u.is_staff)
def templates(request):
    templates = Finding_Template.objects.all()
    templates = TemplateFindingFilter(request.GET, queryset=templates)
    paged_templates = get_page_items(request, templates, 25)
    title_words = [word
                   for finding in templates
                   for word in finding.title.split() if len(word) > 2]

    title_words = sorted(set(title_words))
    add_breadcrumb(title="Template Listing", top_level=True, request=request)
    return render(request, 'dojo/templates.html',
                  {'templates': paged_templates,
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
            template.numerical_severity = Finding.get_numerical_severity(template.severity)
            template.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Template created successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('templates'))
        else:
            messages.add_message(request,
                                 messages.ERROR,
                                 'Template form has error, please revise and try again.',
                                 extra_tags='alert-danger')
    add_breadcrumb(title="Add Template", top_level=False, request=request)
    return render(request, 'dojo/add_template.html',
                  {'form': form,
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
            template.numerical_severity = Finding.get_numerical_severity(template.severity)
            template.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Template updated successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('templates'))
        else:
            messages.add_message(request,
                                 messages.ERROR,
                                 'Template form has error, please revise and try again.',
                                 extra_tags='alert-danger')
    add_breadcrumb(title="Edit Template", top_level=False, request=request)
    return render(request, 'dojo/add_template.html',
                  {'form': form,
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
            template.delete()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Finding Template deleted successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('templates'))
        else:
            messages.add_message(request,
                                 messages.ERROR,
                                 'Unable to delete Template, please revise and try again.',
                                 extra_tags='alert-danger')
    else:
        return HttpResponseForbidden()


@user_passes_test(lambda u: u.is_staff)
def finding_from_template(request, tid):
    template = get_object_or_404(Finding_Template, id=tid)
